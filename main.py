import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import os
import re
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import webbrowser
import yaml
from scanner_engine import FileScanner, PackerFuzzerIntegration

class SensitiveInfoScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("敏感信息扫描工具 v1.2")
        self.root.geometry("1200x800")
        
        # 扫描状态
        self.is_scanning = False
        self.scan_thread = None
        self.result_queue = queue.Queue()
        
        # 扫描结果
        self.scan_results = []
        self.filtered_results = []
        
        # 预览窗口管理
        self.preview_window = None
        self.current_preview_index = -1
        
        # 初始化扫描引擎
        self.scanner = FileScanner(max_workers=4)
        self.packer_fuzzer = PackerFuzzerIntegration()
        
        # 默认规则
        self.default_rules = {
            "API接口": [
                r"/api/[^'\"\\s]+",
                r"\.get\(['\"]([^'\"]+)['\"]",
                r"\.post\(['\"]([^'\"]+)['\"]",
                r"method:\s*['\"]get['\"]",
                r"method:\s*['\"]post['\"]"
            ],
            "密钥信息": [
                r"api[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
                r"secret[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
                r"access[_-]?token['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
                r"private[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]"
            ],
            "邮箱信息": [
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            ],
            "手机号": [
                r"1[3-9]\d{9}",
                r"\+86\s*1[3-9]\d{9}"
            ],
            "IP地址": [
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            ],
            "数据库连接": [
                r"jdbc:[^'\"\\s]+",
                r"mongodb://[^'\"\\s]+",
                r"mysql://[^'\"\\s]+",
                r"postgresql://[^'\"\\s]+"
            ],
            "云服务配置": [
                r"AKIA[0-9A-Z]{16}",  # AWS Access Key
                r"aws_secret_access_key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9/+=]{40})['\"]",
                r"aliyun[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]"
            ]
        }
        
        self.rules = self.load_rules()
        self.setup_gui()
        
    def load_rules(self):
        """加载规则配置"""
        config_file = "scanner_rules.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return self.default_rules.copy()
    
    def save_rules(self):
        """保存规则配置"""
        try:
            with open("scanner_rules.json", 'w', encoding='utf-8') as f:
                json.dump(self.rules, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror("错误", f"保存规则失败: {str(e)}")
    
    def get_active_rules(self):
        """获取所有启用的规则"""
        active_rules = []
        for category, category_data in self.rules.items():
            # 检查分类是否启用
            if isinstance(category_data, dict) and 'enabled' in category_data:
                # 新格式：包含enabled属性的对象
                if not category_data.get('enabled', True):
                    continue  # 跳过禁用的分类
                
                rules_list = category_data.get('rules', [])
                for rule in rules_list:
                    if isinstance(rule, dict):
                        # 检查规则是否启用
                        if rule.get('enabled', True):
                            active_rules.append({
                                'category': category,
                                'pattern': rule.get('pattern', ''),
                                'name': rule.get('name', '未命名规则')
                            })
                    else:
                        # 兼容旧格式规则
                        active_rules.append({
                            'category': category,
                            'pattern': rule,
                            'name': '规则'
                        })
            elif isinstance(category_data, list):
                # 旧格式：直接的规则数组
                for rule in category_data:
                    if isinstance(rule, str):
                        active_rules.append({
                            'category': category,
                            'pattern': rule,
                            'name': '规则'
                        })
            else:
                # 其他格式的兼容处理
                if hasattr(category_data, '__iter__') and not isinstance(category_data, str):
                    for rule in category_data:
                        active_rules.append({
                            'category': category,
                            'pattern': str(rule),
                            'name': '规则'
                        })
        return active_rules
    
    def setup_gui(self):
        """设置GUI界面"""
        # 创建菜单栏
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="导出结果", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        
        # 工具菜单
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="工具", menu=tools_menu)
        tools_menu.add_command(label="Webpack反编译", command=self.open_webpack_tool)
        tools_menu.add_command(label="规则管理", command=self.open_rule_manager)
        
        # 主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 顶部控制面板
        control_frame = ttk.LabelFrame(main_frame, text="扫描控制", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 文件夹选择
        folder_frame = ttk.Frame(control_frame)
        folder_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(folder_frame, text="目标文件夹:").pack(side=tk.LEFT)
        self.folder_var = tk.StringVar()
        folder_entry = ttk.Entry(folder_frame, textvariable=self.folder_var, width=60)
        folder_entry.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        ttk.Button(folder_frame, text="浏览", command=self.select_folder).pack(side=tk.RIGHT)
        
        # 扫描选项
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 文件类型过滤
        ttk.Label(options_frame, text="文件类型:").pack(side=tk.LEFT)
        self.file_types_var = tk.StringVar(value="*.js,*.jsx,*.ts,*.tsx,*.vue,*.html,*.css,*.json,*.xml,*.txt")
        
        # 文件类型显示和选择按钮
        file_type_frame = ttk.Frame(options_frame)
        file_type_frame.pack(side=tk.LEFT, padx=(5, 10))
        
        self.file_types_display = ttk.Entry(file_type_frame, textvariable=self.file_types_var, width=35, state='readonly')
        self.file_types_display.pack(side=tk.LEFT)
        
        ttk.Button(file_type_frame, text="选择", command=self.open_file_type_selector, width=6).pack(side=tk.LEFT, padx=(2, 0))
        
        # 线程数
        ttk.Label(options_frame, text="线程数:").pack(side=tk.LEFT)
        self.thread_count_var = tk.StringVar(value="4")
        tk.Spinbox(options_frame, from_=1, to=16, textvariable=self.thread_count_var, width=5).pack(side=tk.LEFT, padx=(5, 10))
        
        # 控制按钮
        self.start_btn = ttk.Button(options_frame, text="开始扫描", command=self.start_scan)
        self.start_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.stop_btn = ttk.Button(options_frame, text="停止扫描", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.RIGHT)
        
        # 进度条
        self.progress_var = tk.StringVar(value="就绪")
        ttk.Label(control_frame, textvariable=self.progress_var).pack(anchor=tk.W, pady=(5, 0))
        
        # 使用确定模式的进度条，显示百分比
        self.progress_bar = ttk.Progressbar(control_frame, mode='determinate', maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(2, 0))
        
        # 初始化进度相关变量
        self.total_files = 0
        self.scanned_files = 0
        
        # 中间面板 - 分为左右两部分
        middle_frame = ttk.Frame(main_frame)
        middle_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左侧 - 结果筛选
        left_frame = ttk.LabelFrame(middle_frame, text="结果筛选", padding=5)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        
        # 分类筛选
        filter_header_frame = ttk.Frame(left_frame)
        filter_header_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_header_frame, text="按类型筛选:").pack(side=tk.LEFT)
        
        # 全选按钮
        self.select_all_text = tk.StringVar(value="全选")
        self.select_all_btn = ttk.Button(filter_header_frame, textvariable=self.select_all_text, 
                                        command=self.toggle_select_all, width=6)
        self.select_all_btn.pack(side=tk.RIGHT)
        
        # 分类复选框框架 - 带滚动条
        self.category_frame = ttk.Frame(left_frame)
        self.category_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # 创建滚动条
        category_canvas = tk.Canvas(self.category_frame, highlightthickness=0)
        category_scrollbar = ttk.Scrollbar(self.category_frame, orient="vertical", command=category_canvas.yview)
        self.scrollable_category_frame = ttk.Frame(category_canvas)
        
        # 绑定滚动区域更新
        def update_scroll_region(event=None):
            category_canvas.configure(scrollregion=category_canvas.bbox("all"))
        
        self.scrollable_category_frame.bind("<Configure>", update_scroll_region)
        
        # 绑定鼠标滚轮事件
        def on_mousewheel(event):
            category_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        category_canvas.bind("<MouseWheel>", on_mousewheel)
        self.scrollable_category_frame.bind("<MouseWheel>", on_mousewheel)
        
        category_canvas.create_window((0, 0), window=self.scrollable_category_frame, anchor="nw")
        category_canvas.configure(yscrollcommand=category_scrollbar.set)
        
        category_canvas.pack(side="left", fill="both", expand=True)
        category_scrollbar.pack(side="right", fill="y")
        
        # 存储复选框变量
        self.category_vars = {}
        self.category_checkboxes = {}
        
        # 右侧 - 扫描结果
        right_frame = ttk.LabelFrame(middle_frame, text="扫描结果", padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 结果表格 - 使用最简单的布局
        columns = ('文件', '行号', '类型', '内容')
        self.result_tree = ttk.Treeview(right_frame, columns=columns, show='headings', height=20)
        
        # 设置列标题和宽度
        self.result_tree.heading('文件', text='文件名')
        self.result_tree.heading('行号', text='行号')
        self.result_tree.heading('类型', text='类型')
        self.result_tree.heading('内容', text='匹配内容')
        
        # 设置列宽度 - 确保内容可见
        self.result_tree.column('文件', width=200, minwidth=150)
        self.result_tree.column('行号', width=60, minwidth=50)
        self.result_tree.column('类型', width=100, minwidth=80)
        self.result_tree.column('内容', width=600, minwidth=400)
        
        # 添加垂直滚动条 - 简单布局
        result_scrollbar = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=result_scrollbar.set)
        
        # 使用简单的pack布局
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定双击事件
        self.result_tree.bind('<Double-1>', self.on_result_double_click)
        self.result_tree.bind('<Button-1>', self.on_result_single_click)
        
        # 底部状态栏
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
        # 初始化分类列表
        self.update_category_list()
    
    def select_folder(self):
        """选择要扫描的文件夹"""
        folder = filedialog.askdirectory()
        if folder:
            self.folder_var.set(folder)
    
    def start_scan(self):
        """开始扫描"""
        if not self.folder_var.get():
            messagebox.showwarning("警告", "请先选择要扫描的文件夹")
            return
        
        if not os.path.exists(self.folder_var.get()):
            messagebox.showerror("错误", "选择的文件夹不存在")
            return
        
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # 重置进度条为确定模式
        self.progress_bar.config(value=0)
        self.total_files = 0
        self.scanned_files = 0
        self.progress_var.set("准备扫描...")
        
        # 清空之前的结果
        self.scan_results.clear()
        self.filtered_results.clear()
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        
        # 启动扫描线程
        self.scan_thread = threading.Thread(target=self.scan_files, daemon=True)
        self.scan_thread.start()
        
        # 启动结果更新
        self.root.after(100, self.check_scan_results)
    
    def stop_scan(self):
        """停止扫描"""
        self.is_scanning = False
        self.scanner.stop_scan()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        # 不再调用progress_bar.stop()，因为我们使用确定模式
        self.progress_var.set("扫描已停止")
    
    def scan_files(self):
        """扫描文件的主要逻辑"""
        try:
            folder_path = self.folder_var.get()
            file_types = [ft.strip() for ft in self.file_types_var.get().split(',')]
            thread_count = int(self.thread_count_var.get())
            
            # 更新扫描引擎的线程数
            self.scanner.max_workers = thread_count
            
            # 设置回调函数
            self.scanner.set_progress_callback(self.on_progress_update)
            self.scanner.set_result_callback(self.on_result_found)
            
            # 开始扫描 - 使用启用的规则
            active_rules = self.get_active_rules()
            # 转换为旧格式以兼容扫描引擎
            rules_dict = {}
            for rule in active_rules:
                category = rule['category']
                if category not in rules_dict:
                    rules_dict[category] = []
                rules_dict[category].append(rule['pattern'])
            
            self.scanner.scan_files(folder_path, file_types, rules_dict)
            
        except Exception as e:
            self.result_queue.put(('error', f"扫描出错: {str(e)}"))
    
    def on_progress_update(self, message):
        """进度更新回调"""
        if "扫描完成" in message:
            self.result_queue.put(('complete', message))
        else:
            self.result_queue.put(('progress', message))
    
    def on_result_found(self, result):
        """发现结果时的回调"""
        self.result_queue.put(('result', result))
    
    def update_progress_bar(self, message):
        """更新进度条百分比"""
        try:
            # 解析进度消息，格式："已扫描 X/Y 个文件"
            if "已扫描" in message and "/" in message:
                # 提取数字
                import re
                match = re.search(r'已扫描\s+(\d+)/(\d+)\s+个文件', message)
                if match:
                    current = int(match.group(1))
                    total = int(match.group(2))
                    
                    # 更新总文件数（第一次获取时）
                    if self.total_files == 0:
                        self.total_files = total
                    
                    # 计算百分比
                    if total > 0:
                        percentage = (current / total) * 100
                        self.progress_bar.config(value=percentage)
                        
                        # 更新进度文本，包含百分比
                        progress_text = f"已扫描 {current}/{total} 个文件 ({percentage:.1f}%)"
                        self.progress_var.set(progress_text)
                        
        except Exception as e:
            # 如果解析失败，保持原始消息
            print(f"解析进度消息失败: {e}")
            pass
    

    
    def check_scan_results(self):
        """检查扫描结果队列"""
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                
                if msg_type == 'result':
                    self.scan_results.append(data)
                elif msg_type == 'progress':
                    self.progress_var.set(data)
                    # 解析进度信息并更新进度条
                    self.update_progress_bar(data)
                elif msg_type == 'complete':
                    self.stop_scan()
                    # 设置进度条为100%
                    self.progress_bar.config(value=100)
                    self.progress_var.set(data)
                    # 更新分类列表并显示结果
                    self.update_category_list()
                    messagebox.showinfo("完成", data)
                elif msg_type == 'error':
                    self.stop_scan()
                    messagebox.showerror("错误", data)
                    
        except queue.Empty:
            pass
        
        if self.is_scanning:
            self.root.after(100, self.check_scan_results)
    
    def add_result_to_tree(self, result):
        """添加结果到树形控件"""
        try:
            # 简化内容显示
            content = result['content'].strip()
            if len(content) > 100:
                content = content[:100] + '...'
            
            # 直接插入，不使用tags
            self.result_tree.insert('', 'end', values=(
                result['file'],
                str(result['line']),
                result['category'],
                content
            ))
        except Exception as e:
            print(f"添加结果失败: {str(e)}")
    
    def update_category_list(self):
        """更新分类列表"""
        # 清除现有的复选框
        for checkbox in self.category_checkboxes.values():
            checkbox.destroy()
        self.category_vars.clear()
        self.category_checkboxes.clear()
        
        # 获取所有分类
        categories = set()
        for result in self.scan_results:
            categories.add(result['category'])
        
        # 创建复选框
        for i, category in enumerate(sorted(categories)):
            var = tk.BooleanVar(value=True)  # 默认选中
            self.category_vars[category] = var
            
            checkbox = ttk.Checkbutton(
                self.scrollable_category_frame,
                text=category,
                variable=var,
                command=self.filter_results
            )
            checkbox.grid(row=i, column=0, sticky='w', padx=5, pady=2)
            self.category_checkboxes[category] = checkbox
        
        # 确保滚动区域更新
        self.scrollable_category_frame.update_idletasks()
        # 手动触发滚动区域重新配置
        if hasattr(self, 'category_frame'):
            category_canvas = None
            for widget in self.category_frame.winfo_children():
                if isinstance(widget, tk.Canvas):
                    category_canvas = widget
                    break
            if category_canvas:
                category_canvas.configure(scrollregion=category_canvas.bbox("all"))
        
        # 扫描完成后立即过滤结果以显示
        if categories:  # 只有当有分类时才过滤
            # 使用after确保复选框状态已经设置完毕
            self.root.after(50, self.filter_results)
        else:
            # 如果没有分类，直接显示所有结果
            self.filtered_results = self.scan_results.copy()
            for item in self.result_tree.get_children():
                self.result_tree.delete(item)
            for result in self.filtered_results:
                self.add_result_to_tree(result)
    
    def filter_results(self, event=None):
        """根据选择的分类筛选结果"""
        # 获取选中的分类
        selected_categories = []
        for category, var in self.category_vars.items():
            if var.get():
                selected_categories.append(category)
        
        # 过滤结果
        if not selected_categories:
            # 如果没有选择任何分类，不显示任何结果
            self.filtered_results = []
        else:
            self.filtered_results = [r for r in self.scan_results if r['category'] in selected_categories]
        
        # 清空现有显示
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        
        # 限制显示数量，避免界面卡死
        max_display = 1000  # 最多显示1000条
        display_results = self.filtered_results[:max_display]
        
        # 直接添加结果
        for result in display_results:
            self.add_result_to_tree(result)
        
        # 如果结果被截断，显示提示
        if len(self.filtered_results) > max_display:
            self.result_tree.insert('', 'end', values=(
                "...", "...", "提示", f"还有 {len(self.filtered_results) - max_display} 条结果未显示"
            ))
        
        # 强制刷新界面
        self.root.update_idletasks()
    
    def toggle_select_all(self):
        """切换全选/取消全选"""
        # 检查当前状态
        all_selected = all(var.get() for var in self.category_vars.values()) if self.category_vars else False
        
        if all_selected:
            # 如果全部选中，则取消全选
            for var in self.category_vars.values():
                var.set(False)
            self.select_all_text.set("全选")
        else:
            # 如果不是全部选中，则全选
            for var in self.category_vars.values():
                var.set(True)
            self.select_all_text.set("取消")
        
        # 更新筛选结果
        self.filter_results()
    
    def open_file_type_selector(self):
        """打开文件类型选择器"""
        FileTypeSelectorWindow(self.root, self.file_types_var, self)
    
    def filter_results_by_file_type(self, selected_file_types):
        """根据选择的文件类型过滤结果"""
        if not self.scan_results:
            return
        
        # 将文件类型转换为扩展名集合
        extensions = set()
        for file_type in selected_file_types:
            # 移除*号，只保留扩展名
            ext = file_type.replace('*', '') if file_type.startswith('*') else file_type
            extensions.add(ext)
        
        # 过滤结果
        filtered_results = []
        for result in self.scan_results:
            file_path = result.get('file', '')
            # 检查文件扩展名是否匹配
            file_ext = os.path.splitext(file_path)[1].lower()
            if any(ext.lower() == file_ext for ext in extensions):
                filtered_results.append(result)
        
        # 更新过滤后的结果并刷新显示
        self.filtered_results = filtered_results
        self.display_results()
    

    
    def on_result_single_click(self, event):
        """单击结果项 - 显示预览"""
        # 使用after方法避免界面阻塞，立即响应
        self.root.after(1, self._handle_single_click_preview)
    
    def _handle_single_click_preview(self):
        """处理单击预览逻辑"""
        selection = self.result_tree.selection()
        if selection:
            item = self.result_tree.item(selection[0])
            values = item['values']
            
            # 找到对应的完整结果在filtered_results中的索引
            for i, result in enumerate(self.filtered_results):
                if (result['file'] == values[0] and 
                    str(result['line']) == str(values[1]) and 
                    result['category'] == values[2]):
                    
                    self.current_preview_index = i
                    self.show_preview_window()
                    return
            
            # 如果在filtered_results中没找到，说明可能是筛选问题，直接用scan_results
            for i, result in enumerate(self.scan_results):
                if (result['file'] == values[0] and 
                    str(result['line']) == str(values[1]) and 
                    result['category'] == values[2]):
                    
                    # 临时设置filtered_results为包含这个结果
                    self.filtered_results = [result]
                    self.current_preview_index = 0
                    self.show_preview_window()
                    break
    
    def on_result_double_click(self, event):
        """双击结果项 - 打开文件并跳转到指定行"""
        selection = self.result_tree.selection()
        if selection:
            item = self.result_tree.item(selection[0])
            values = item['values']
            
            # 找到对应的完整结果
            for result in self.scan_results:
                if (result['file'] == values[0] and 
                    str(result['line']) == str(values[1]) and 
                    result['category'] == values[2]):
                    
                    self.open_file_at_line(result['full_path'], result['line'])
                    break
    
    def show_preview_window(self):
        """显示预览窗口（单例模式）"""
        if not self.filtered_results or self.current_preview_index < 0:
            return
            
        result = self.filtered_results[self.current_preview_index]
        
        # 如果预览窗口不存在，创建新窗口
        if self.preview_window is None or not self.preview_window.winfo_exists():
            self.create_preview_window()
        
        # 更新窗口内容
        self.update_preview_content(result)
        
        # 确保窗口可见但不强制置于前台
        self.preview_window.deiconify()
        self.preview_window.focus_force()
    
    def create_preview_window(self):
        """创建预览窗口"""
        self.preview_window = tk.Toplevel(self.root)
        self.preview_window.geometry("900x650")
        
        # 窗口居中显示
        self.center_window(self.preview_window, 900, 650)
        
        # 创建主框架
        main_frame = ttk.Frame(self.preview_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 标题和导航框架
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 文件名标签
        self.preview_title = ttk.Label(header_frame, text="", font=('', 12, 'bold'))
        self.preview_title.pack(side=tk.LEFT)
        
        # 导航按钮框架
        nav_frame = ttk.Frame(header_frame)
        nav_frame.pack(side=tk.RIGHT)
        
        self.prev_btn = ttk.Button(nav_frame, text="◀ 上一个", command=self.preview_previous, width=10)
        self.prev_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.next_btn = ttk.Button(nav_frame, text="下一个 ▶", command=self.preview_next, width=10)
        self.next_btn.pack(side=tk.LEFT)
        
        # 信息标签框架
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.info_label = ttk.Label(info_frame, text="", font=('', 10))
        self.info_label.pack(side=tk.LEFT)
        
        # 代码显示区域
        self.preview_text = scrolledtext.ScrolledText(
            main_frame, 
            wrap=tk.NONE, 
            font=('Consolas', 10),
            selectbackground='#0078D4',  # VS Code风格的蓝色背景
            selectforeground='white',    # 白色前景文字
            selectborderwidth=0,         # 去掉边框，更像VS Code
            state=tk.NORMAL,
            cursor='xterm',              # 设置文本光标
            inactiveselectbackground='#264F78',  # 失去焦点时的深蓝色背景
            relief='flat',               # 扁平样式
            borderwidth=0                # 去掉边框
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 配置高亮样式
        self.preview_text.tag_config('highlight', background='yellow', foreground='red')
        
        # 配置VS Code风格的选中样式
        self.preview_text.tag_config('selected_line', background='#0078D4', foreground='white')
        self.preview_text.tag_config('current_line', background='#2D2D30', foreground='white')
        
        # 绑定选择事件，显示选中状态
        self.preview_text.bind('<<Selection>>', self.on_text_selection)
        self.preview_text.bind('<Button-1>', self.on_text_click)
        self.preview_text.bind('<ButtonRelease-1>', self.on_text_selection)
        self.preview_text.bind('<KeyRelease>', self.on_text_selection)
        
        # 绑定键盘快捷键
        self.preview_text.bind('<Control-a>', self.select_all_text)  # Ctrl+A 全选
        self.preview_text.bind('<Control-c>', self.copy_selected_text)  # Ctrl+C 复制
        
        # 绑定ESC键关闭窗口
        self.preview_window.bind('<Escape>', self.close_preview_window)
        self.preview_text.bind('<Escape>', self.close_preview_window)
        
        # 确保窗口能接收键盘事件
        self.preview_window.focus_set()
        
        # 创建右键菜单
        self.create_context_menu()
    
    def select_all_text(self, event=None):
        """全选文本"""
        if hasattr(self, 'preview_text') and self.preview_text.winfo_exists():
            self.preview_text.tag_add(tk.SEL, "1.0", tk.END)
            self.preview_text.mark_set(tk.INSERT, "1.0")
            self.preview_text.see(tk.INSERT)
        return 'break'  # 阻止默认事件处理
    
    def copy_selected_text(self, event=None):
        """复制选中的文本"""
        if hasattr(self, 'preview_text') and self.preview_text.winfo_exists():
            try:
                selected_text = self.preview_text.selection_get()
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
                print("已复制选中文本到剪贴板")
            except tk.TclError:
                # 没有选中文本时，复制全部内容
                all_text = self.preview_text.get("1.0", tk.END)
                self.root.clipboard_clear()
                self.root.clipboard_append(all_text)
                print("已复制全部文本到剪贴板")
        return 'break'  # 阻止默认事件处理
    
    def on_text_selection(self, event=None):
        """文本选择事件处理"""
        try:
            if hasattr(self, 'preview_text') and self.preview_text.winfo_exists():
                # 获取选中的文本
                selected_text = self.preview_text.selection_get()
                if selected_text:
                    # 在状态栏或标题显示选中的字符数
                    char_count = len(selected_text)
                    line_count = selected_text.count('\n') + 1
                    self.preview_window.title(f"预览 - 已选中 {char_count} 个字符，{line_count} 行")
        except tk.TclError:
            # 没有选中文本时恢复原标题
            if hasattr(self, 'preview_window') and self.preview_window.winfo_exists():
                if hasattr(self, 'current_preview_index') and self.current_preview_index >= 0:
                    result = self.filtered_results[self.current_preview_index]
                    self.preview_window.title(f"预览 - {result['file']}")
    
    def on_text_click(self, event=None):
        """鼠标点击事件处理"""
        # 延迟检查选择状态，因为点击事件可能清除选择
        self.preview_text.after(10, self.on_text_selection)
    
    def close_preview_window(self, event=None):
        """关闭预览窗口"""
        if hasattr(self, 'preview_window') and self.preview_window.winfo_exists():
            self.preview_window.withdraw()  # 隐藏窗口而不是销毁
        return 'break'  # 阻止默认事件处理
    
    def copy_current_line(self):
        """复制当前行"""
        if hasattr(self, 'preview_text') and self.preview_text.winfo_exists():
            # 获取光标位置
            cursor_pos = self.preview_text.index(tk.INSERT)
            line_start = cursor_pos.split('.')[0] + '.0'
            line_end = cursor_pos.split('.')[0] + '.end'
            
            # 获取当前行内容
            line_text = self.preview_text.get(line_start, line_end)
            self.root.clipboard_clear()
            self.root.clipboard_append(line_text)
            print("已复制当前行到剪贴板")
    
    def copy_all_text(self):
        """复制全部文本"""
        if hasattr(self, 'preview_text') and self.preview_text.winfo_exists():
            all_text = self.preview_text.get("1.0", tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(all_text)
            print("已复制全部文本到剪贴板")
         
          # 底部按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        self.open_file_btn = ttk.Button(button_frame, text="打开文件", command=self.open_current_file)
        self.open_file_btn.pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="关闭", command=self.close_preview_window).pack(side=tk.RIGHT)
        
        # 绑定关闭事件
        self.preview_window.protocol("WM_DELETE_WINDOW", self.close_preview_window)
    
    def create_context_menu(self):
        """创建右键菜单"""
        self.context_menu = tk.Menu(self.preview_text, tearoff=0)
        self.context_menu.add_command(label="复制选中", command=self.copy_selected_text, accelerator="Ctrl+C")
        self.context_menu.add_command(label="全选", command=self.select_all_text, accelerator="Ctrl+A")
        self.context_menu.add_separator()
        self.context_menu.add_command(label="复制当前行", command=self.copy_current_line)
        self.context_menu.add_command(label="复制全部", command=self.copy_all_text)
        
        # 绑定右键菜单
        self.preview_text.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        """显示右键菜单"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
    
    def copy_text(self):
        """复制选中的文本"""
        try:
            selected_text = self.preview_text.selection_get()
            self.preview_window.clipboard_clear()
            self.preview_window.clipboard_append(selected_text)
        except tk.TclError:
            # 没有选中文本
            pass
    
    def select_all_text(self):
        """全选文本"""
        self.preview_text.tag_add(tk.SEL, "1.0", tk.END)
        self.preview_text.mark_set(tk.INSERT, "1.0")
        self.preview_text.see(tk.INSERT)
    
    def copy_current_line(self):
        """复制当前光标所在行"""
        current_line = self.preview_text.index(tk.INSERT).split('.')[0]
        line_start = f"{current_line}.0"
        line_end = f"{current_line}.end"
        line_text = self.preview_text.get(line_start, line_end)
        
        self.preview_window.clipboard_clear()
        self.preview_window.clipboard_append(line_text)
    
    def copy_selected_lines(self):
        """复制选中的完整行"""
        try:
            # 获取选中区域的起始和结束位置
            sel_start = self.preview_text.index(tk.SEL_FIRST)
            sel_end = self.preview_text.index(tk.SEL_LAST)
            
            # 获取起始行和结束行
            start_line = int(sel_start.split('.')[0])
            end_line = int(sel_end.split('.')[0])
            
            # 获取完整行的内容
            lines = []
            for line_num in range(start_line, end_line + 1):
                line_start = f"{line_num}.0"
                line_end = f"{line_num}.end"
                line_text = self.preview_text.get(line_start, line_end)
                lines.append(line_text)
            
            full_text = '\n'.join(lines)
            self.preview_window.clipboard_clear()
            self.preview_window.clipboard_append(full_text)
            
        except tk.TclError:
            # 没有选中文本，复制当前行
            self.copy_current_line()
    
    def center_window(self, window, width, height):
        """将窗口居中显示"""
        # 获取屏幕尺寸
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        
        # 计算居中位置
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        window.geometry(f"{width}x{height}+{x}+{y}")
    
    def update_preview_content(self, result):
        """更新预览窗口内容"""
        # 更新标题
        filename = os.path.basename(result['full_path'])
        self.preview_window.title(f"预览 - {filename}")
        self.preview_title.config(text=filename)
        
        # 更新信息
        current_num = self.current_preview_index + 1
        total_num = len(self.filtered_results)
        info_text = f"第 {current_num}/{total_num} 项 | 行号: {result['line']} | 类型: {result['category']}"
        self.info_label.config(text=info_text)
        
        # 更新导航按钮状态
        self.prev_btn.config(state=tk.NORMAL if self.current_preview_index > 0 else tk.DISABLED)
        self.next_btn.config(state=tk.NORMAL if self.current_preview_index < len(self.filtered_results) - 1 else tk.DISABLED)
        
        # 清空并更新代码内容
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete(1.0, tk.END)
        
        try:
            with open(result['full_path'], 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            target_line = result['line'] - 1  # 转换为0索引
            start_line = max(0, target_line - 50)
            end_line = min(len(lines), target_line + 51)
            
            # 插入代码内容
            for i in range(start_line, end_line):
                line_num = i + 1
                line_content = lines[i].rstrip('\n\r')
                
                # 高亮目标行
                if i == target_line:
                    self.preview_text.insert(tk.END, f"{line_num:4d}: {line_content}\n", 'highlight')
                else:
                    self.preview_text.insert(tk.END, f"{line_num:4d}: {line_content}\n")
            
            # 滚动到目标行
            target_line_in_widget = target_line - start_line + 1
            self.preview_text.see(f"{target_line_in_widget}.0")
            
        except Exception as e:
            self.preview_text.insert(1.0, f"无法读取文件内容: {str(e)}")
        
        self.preview_text.config(state=tk.DISABLED)
    
    def preview_previous(self):
        """预览上一个结果"""
        if self.current_preview_index > 0:
            self.current_preview_index -= 1
            result = self.filtered_results[self.current_preview_index]
            self.update_preview_content(result)
    
    def preview_next(self):
        """预览下一个结果"""
        if self.current_preview_index < len(self.filtered_results) - 1:
            self.current_preview_index += 1
            result = self.filtered_results[self.current_preview_index]
            self.update_preview_content(result)
    
    def open_current_file(self):
        """打开当前预览的文件"""
        if self.current_preview_index >= 0 and self.current_preview_index < len(self.filtered_results):
            result = self.filtered_results[self.current_preview_index]
            self.open_file_at_line(result['full_path'], result['line'])
    
    def close_preview_window(self):
        """关闭预览窗口"""
        if self.preview_window and self.preview_window.winfo_exists():
            self.preview_window.destroy()
        self.preview_window = None
        self.current_preview_index = -1
    
    def open_file_at_line(self, file_path, line_number):
        """打开文件并跳转到指定行"""
        try:
            # 尝试使用系统默认编辑器
            if sys.platform == "win32":
                # Windows - 尝试使用notepad++或记事本
                try:
                    subprocess.run(['notepad++', f'-n{line_number}', file_path], check=True)
                except:
                    subprocess.run(['notepad', file_path])
            elif sys.platform == "darwin":
                # macOS
                subprocess.run(['open', file_path])
            else:
                # Linux
                subprocess.run(['xdg-open', file_path])
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件: {str(e)}")
    
    def open_rule_manager(self):
        """打开规则管理窗口"""
        RuleManagerWindow(self.root, self.rules, self.save_rules)
    
    def open_webpack_tool(self):
        """打开Webpack工具窗口"""
        WebpackToolWindow(self.root)
    
    def export_results(self):
        """导出扫描结果"""
        if not self.scan_results:
            messagebox.showwarning("警告", "没有可导出的结果")
            return
        
        # 创建格式选择窗口
        ExportFormatWindow(self.root, self.scan_results)
    
    def run(self):
        """运行应用程序"""
        self.root.mainloop()


class RuleManagerWindow:
    def __init__(self, parent, rules, save_callback):
        self.rules = rules.copy()  # 创建副本以便取消时不影响原数据
        self.save_callback = save_callback
        
        # 确保每个分类和规则都有enabled属性
        self.ensure_enabled_attributes()
        
        self.window = tk.Toplevel(parent)
        self.window.title("规则管理")
        self.window.transient(parent)
        self.window.grab_set()
        
        # 窗口居中显示
        self.center_window(800, 600)
        
        self.setup_gui()
    
    def center_window(self, width, height):
        """将窗口居中显示"""
        # 获取屏幕尺寸
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        # 计算居中位置
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.window.geometry(f"{width}x{height}+{x}+{y}")
    
    def ensure_enabled_attributes(self):
        """确保所有分类和规则都有enabled属性"""
        for category, rules in self.rules.items():
            # 为分类添加enabled属性（如果没有的话）
            if not isinstance(rules, dict) or 'enabled' not in rules:
                # 转换旧格式为新格式
                old_rules = rules if isinstance(rules, list) else []
                self.rules[category] = {
                    'enabled': True,
                    'rules': []
                }
                # 转换规则格式
                for rule in old_rules:
                    if isinstance(rule, str):
                        self.rules[category]['rules'].append({
                            'name': f'规则{len(self.rules[category]["rules"])+1}',
                            'pattern': rule,
                            'enabled': True
                        })
                    elif isinstance(rule, dict):
                        if 'enabled' not in rule:
                            rule['enabled'] = True
                        if 'name' not in rule:
                            rule['name'] = f'规则{len(self.rules[category]["rules"])+1}'
                        self.rules[category]['rules'].append(rule)
            else:
                # 确保规则列表中的每个规则都有enabled属性
                for rule in self.rules[category].get('rules', []):
                    if 'enabled' not in rule:
                        rule['enabled'] = True
                    if 'name' not in rule:
                        rule['name'] = f'规则{len(self.rules[category]["rules"])}'
    
    def setup_gui(self):
        """设置规则管理界面"""
        # 主框架
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 左侧 - 分类列表
        left_frame = ttk.LabelFrame(main_frame, text="规则分类", padding=5)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        
        # 分类列表 - 使用Treeview显示启用状态
        cat_columns = ('enabled', 'name')
        self.category_tree = ttk.Treeview(left_frame, columns=cat_columns, show='headings')
        
        # 设置列标题
        self.category_tree.heading('enabled', text='启用')
        self.category_tree.heading('name', text='分类名称')
        
        # 设置列宽
        self.category_tree.column('enabled', width=50, anchor='center')
        self.category_tree.column('name', width=120)
        
        self.category_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        self.category_tree.bind('<<TreeviewSelect>>', self.on_category_select)
        self.category_tree.bind('<Button-1>', self.on_category_click)
        
        # 分类操作按钮
        cat_btn_frame = ttk.Frame(left_frame)
        cat_btn_frame.pack(fill=tk.X)
        ttk.Button(cat_btn_frame, text="添加分类", command=self.add_category).pack(fill=tk.X, pady=(0, 2))
        ttk.Button(cat_btn_frame, text="启用/禁用", command=self.toggle_category).pack(fill=tk.X, pady=(0, 2))
        ttk.Button(cat_btn_frame, text="删除分类", command=self.delete_category).pack(fill=tk.X, pady=(0, 2))
        
        # 全选/取消全选按钮
        select_frame = ttk.Frame(cat_btn_frame)
        select_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(select_frame, text="全选", command=self.select_all_categories).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        ttk.Button(select_frame, text="取消全选", command=self.deselect_all_categories).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 右侧 - 规则列表
        right_frame = ttk.LabelFrame(main_frame, text="规则列表", padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 头部区域 - 当前分类和添加规则按钮
        header_frame = ttk.Frame(right_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # 左侧 - 当前分类显示
        category_frame = ttk.Frame(header_frame)
        category_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.current_category_var = tk.StringVar()
        ttk.Label(category_frame, text="当前分类:").pack(anchor=tk.W)
        ttk.Label(category_frame, textvariable=self.current_category_var, font=('', 10, 'bold')).pack(anchor=tk.W)
        
        # 操作提示
        ttk.Label(category_frame, text="提示：双击编辑规则，右键查看更多选项", 
                 font=('', 8), foreground='gray').pack(anchor=tk.W, pady=(2, 0))
        
        # 右侧 - 操作按钮
        action_frame = ttk.Frame(header_frame)
        action_frame.pack(side=tk.RIGHT)
        
        ttk.Button(action_frame, text="+ 添加规则", command=self.add_rule_dialog, width=12).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_frame, text="X 删除规则", command=self.delete_rule, width=12).pack(side=tk.LEFT)
        
        # 规则列表 - 使用Treeview来显示更多信息
        columns = ('enabled', 'name', 'pattern')
        self.rule_tree = ttk.Treeview(right_frame, columns=columns, show='headings', height=10)
        
        # 设置列标题
        self.rule_tree.heading('enabled', text='启用')
        self.rule_tree.heading('name', text='规则名称')
        self.rule_tree.heading('pattern', text='正则表达式')
        
        # 设置列宽
        self.rule_tree.column('enabled', width=50, anchor='center')
        self.rule_tree.column('name', width=120)
        self.rule_tree.column('pattern', width=300)
        
        # 添加滚动条
        rule_scrollbar = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.rule_tree.yview)
        self.rule_tree.configure(yscrollcommand=rule_scrollbar.set)
        
        # 布局
        self.rule_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=(0, 5))
        rule_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 5))
        
        # 绑定点击事件
        self.rule_tree.bind('<Double-1>', self.edit_rule)
        self.rule_tree.bind('<Button-1>', self.on_rule_click)
        self.rule_tree.bind('<Button-3>', self.show_rule_context_menu)  # 右键菜单
        
        # 创建右键菜单
        self.create_rule_context_menu()
        
        # 规则操作按钮
        rule_btn_frame = ttk.Frame(right_frame)
        rule_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 左侧操作按钮
        ttk.Button(rule_btn_frame, text="启用/禁用", command=self.toggle_rule, width=12).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(rule_btn_frame, text="测试规则", command=self.test_rule, width=12).pack(side=tk.LEFT, padx=(0, 5))
        
        # 右侧危险操作按钮
        danger_frame = ttk.Frame(rule_btn_frame)
        danger_frame.pack(side=tk.RIGHT)
        delete_btn = ttk.Button(danger_frame, text="删除选中规则", command=self.delete_rule, width=15)
        delete_btn.pack()
        
        # 底部按钮
        bottom_frame = ttk.Frame(self.window)
        bottom_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(bottom_frame, text="保存", command=self.save_rules).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(bottom_frame, text="取消", command=self.window.destroy).pack(side=tk.RIGHT)
        ttk.Button(bottom_frame, text="导入YAML", command=self.import_yaml_rules).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(bottom_frame, text="恢复默认", command=self.restore_defaults).pack(side=tk.LEFT)
        
        # 初始化界面
        self.refresh_categories()
    
    def refresh_categories(self):
        """刷新分类列表"""
        # 清空现有项目
        for item in self.category_tree.get_children():
            self.category_tree.delete(item)
        
        # 添加分类项目
        for category in sorted(self.rules.keys()):
            # 处理不同的规则数据格式
            if isinstance(self.rules[category], dict):
                enabled = self.rules[category].get('enabled', True)
            else:
                # 如果是列表格式，默认启用
                enabled = True
            
            status = '☑' if enabled else '☐'
            item_id = self.category_tree.insert('', 'end', values=(status, category))
            
            # 如果禁用，设置为灰色
            if not enabled:
                self.category_tree.set(item_id, 'enabled', '☐')
                self.category_tree.item(item_id, tags=('disabled',))
        
        # 配置标签样式
        self.category_tree.tag_configure('disabled', foreground='gray')
    
    def on_category_select(self, event=None):
        """选择分类时的处理"""
        selection = self.category_tree.selection()
        if selection:
                    item = self.category_tree.item(selection[0])
        category = item['values'][1]  # 分类名称现在在第二列
        self.current_category_var.set(category)
        self.refresh_rules(category)
    
    def on_category_click(self, event):
        """分类点击事件 - 处理复选框点击"""
        region = self.category_tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.category_tree.identify_column(event.x)
            if column == '#1':  # 点击了启用列
                item = self.category_tree.identify_row(event.y)
                if item:
                    values = self.category_tree.item(item)['values']
                    category = values[1]
                    
                    # 确保分类数据结构正确
                    if category in self.rules:
                        if not isinstance(self.rules[category], dict):
                            # 转换旧格式为新格式
                            old_rules = self.rules[category]
                            self.rules[category] = {
                                'enabled': True,
                                'rules': [{'name': f'规则{i+1}', 'pattern': rule, 'enabled': True} 
                                         for i, rule in enumerate(old_rules)]
                            }
                        
                        # 切换状态
                        self.rules[category]['enabled'] = not self.rules[category].get('enabled', True)
                        self.refresh_categories()
                        
                        # 如果当前选中的分类被切换，刷新规则列表
                        if self.current_category_var.get() == category:
                            self.refresh_rules(category)
    
    def on_rule_click(self, event):
        """规则点击事件 - 处理复选框点击"""
        region = self.rule_tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.rule_tree.identify_column(event.x)
            if column == '#1':  # 点击了启用列
                item = self.rule_tree.identify_row(event.y)
                if item:
                    values = self.rule_tree.item(item)['values']
                    rule_name = values[1]
                    category = self.current_category_var.get()
                    
                    # 找到并切换规则状态
                    if category in self.rules and isinstance(self.rules[category], dict):
                        rules_list = self.rules[category].get('rules', [])
                        for rule in rules_list:
                            if isinstance(rule, dict) and rule.get('name') == rule_name:
                                rule['enabled'] = not rule.get('enabled', True)
                                break
                        
                        self.refresh_rules(category)
    
    def refresh_rules(self, category):
        """刷新规则列表"""
        # 清空现有项目
        for item in self.rule_tree.get_children():
            self.rule_tree.delete(item)
        
        if category in self.rules:
            # 处理不同的规则数据格式
            if isinstance(self.rules[category], dict):
                rules_list = self.rules[category].get('rules', [])
            else:
                # 如果是列表格式，直接使用
                rules_list = self.rules[category]
            
            for i, rule in enumerate(rules_list):
                if isinstance(rule, dict):
                    # 新格式：字典包含name, pattern, enabled
                    name = rule.get('name', f'规则{i+1}')
                    enabled = rule.get('enabled', True)
                    pattern = rule.get('pattern', str(rule))
                elif isinstance(rule, str):
                    # 旧格式：直接是正则表达式字符串
                    name = f'规则{i+1}'
                    enabled = True
                    pattern = rule
                else:
                    # 其他格式，转换为字符串
                    name = f'规则{i+1}'
                    enabled = True
                    pattern = str(rule)
                
                status = '☑' if enabled else '☐'
                item_id = self.rule_tree.insert('', 'end', values=(status, name, pattern))
                
                # 如果禁用，设置为灰色
                if not enabled:
                    self.rule_tree.item(item_id, tags=('disabled',))
        
        # 配置标签样式
        self.rule_tree.tag_configure('disabled', foreground='gray')
    
    def add_category(self):
        """添加新分类"""
        from tkinter import simpledialog
        dialog = simpledialog.askstring("添加分类", "请输入新分类名称:")
        if dialog and dialog.strip():
            category = dialog.strip()
            if category not in self.rules:
                self.rules[category] = {'enabled': True, 'rules': []}
                self.refresh_categories()
                # 选中新添加的分类
                for item in self.category_tree.get_children():
                    values = self.category_tree.item(item)['values']
                    if values[1] == category:  # 分类名称在第二列
                        self.category_tree.selection_set(item)
                        self.current_category_var.set(category)
                        self.refresh_rules(category)
                        break
            else:
                messagebox.showwarning("警告", "分类已存在")
    
    def delete_category(self):
        """删除分类"""
        selection = self.category_tree.selection()
        if selection:
            item = self.category_tree.item(selection[0])
            category = item['values'][1]  # 分类名称在第二列
            if messagebox.askyesno("确认", f"确定要删除分类 '{category}' 吗？"):
                del self.rules[category]
                self.refresh_categories()
                self.current_category_var.set("")
                # 清空规则列表
                for item in self.rule_tree.get_children():
                    self.rule_tree.delete(item)
    
    def add_rule(self):
        """添加新规则"""
        category = self.current_category_var.get()
        if not category:
            messagebox.showwarning("警告", "请先选择一个分类")
            return
        
        # 打开添加规则对话框
        AddRuleDialog(self.window, category, self.add_rule_callback)
    
    def add_rule_callback(self, category, rule_name, rule_pattern):
        """添加规则的回调函数"""
        # 确保分类数据结构正确
        if not isinstance(self.rules[category], dict):
            old_rules = self.rules[category]
            self.rules[category] = {
                'enabled': True,
                'rules': [{'name': f'规则{i+1}', 'pattern': rule, 'enabled': True} 
                         for i, rule in enumerate(old_rules)]
            }
        
        # 添加新规则
        new_rule = {
            'name': rule_name,
            'pattern': rule_pattern,
            'enabled': True
        }
        
        self.rules[category]['rules'].append(new_rule)
        self.refresh_rules(category)
    
    def delete_rule(self):
        """删除规则"""
        selection = self.rule_tree.selection()
        current_category = self.current_category_var.get()
        
        if not selection:
            messagebox.showwarning("警告", "请先选择一个规则")
            return
            
        if not current_category:
            messagebox.showwarning("警告", "请先选择一个分类")
            return
        
        # 获取选中的规则信息
        item = self.rule_tree.item(selection[0])
        rule_name = item['values'][1]  # 规则名称在第二列
        rule_pattern = item['values'][2]  # 正则表达式在第三列
        
        if messagebox.askyesno("确认删除", f"确定要删除规则 '{rule_name}' 吗？\n\n正则表达式: {rule_pattern}\n\n此操作无法撤销！"):
            try:
                # 获取规则列表
                if isinstance(self.rules[current_category], dict):
                    rules_list = self.rules[current_category].get('rules', [])
                else:
                    rules_list = self.rules[current_category]
                
                # 找到并删除规则
                for i, rule in enumerate(rules_list):
                    if isinstance(rule, dict):
                        if rule.get('pattern') == rule_pattern:
                            rules_list.pop(i)
                            break
                    elif isinstance(rule, str) and rule == rule_pattern:
                        rules_list.pop(i)
                        break
                
                # 刷新显示
                self.refresh_rules(current_category)
                messagebox.showinfo("成功", f"已删除规则: {rule_name}")
                
            except Exception as e:
                messagebox.showerror("错误", f"删除规则失败: {str(e)}")
    
    def create_rule_context_menu(self):
        """创建规则右键菜单"""
        self.rule_context_menu = tk.Menu(self.rule_tree, tearoff=0)
        self.rule_context_menu.add_command(label="编辑规则", command=self.edit_rule)
        self.rule_context_menu.add_command(label="启用/禁用", command=self.toggle_rule)
        self.rule_context_menu.add_separator()
        self.rule_context_menu.add_command(label="测试规则", command=self.test_rule)
        self.rule_context_menu.add_separator()
        self.rule_context_menu.add_command(label="删除规则", command=self.delete_rule)
    
    def show_rule_context_menu(self, event):
        """显示规则右键菜单"""
        # 选中右键点击的项目
        item = self.rule_tree.identify_row(event.y)
        if item:
            self.rule_tree.selection_set(item)
            try:
                self.rule_context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.rule_context_menu.grab_release()
    
    def test_rule(self):
        """测试规则"""
        rule_selection = self.rule_listbox.curselection()
        if not rule_selection:
            messagebox.showwarning("警告", "请先选择一个规则")
            return
        
        rule = self.rule_listbox.get(rule_selection[0])
        
        # 创建测试窗口
        test_window = tk.Toplevel(self.window)
        test_window.title("测试规则")
        test_window.geometry("500x400")
        
        ttk.Label(test_window, text=f"规则: {rule}").pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Label(test_window, text="测试文本:").pack(anchor=tk.W, padx=10)
        test_text = scrolledtext.ScrolledText(test_window, height=10)
        test_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(test_window, text="匹配结果:").pack(anchor=tk.W, padx=10)
        result_text = scrolledtext.ScrolledText(test_window, height=8)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def run_test():
            text = test_text.get(1.0, tk.END)
            result_text.delete(1.0, tk.END)
            
            try:
                matches = re.finditer(rule, text, re.IGNORECASE | re.MULTILINE)
                match_count = 0
                for match in matches:
                    match_count += 1
                    result_text.insert(tk.END, f"匹配 {match_count}: {match.group()}\n")
                    result_text.insert(tk.END, f"位置: {match.start()}-{match.end()}\n\n")
                
                if match_count == 0:
                    result_text.insert(tk.END, "没有找到匹配项")
                    
            except re.error as e:
                result_text.insert(tk.END, f"正则表达式错误: {str(e)}")
        
        ttk.Button(test_window, text="测试", command=run_test).pack(pady=5)
    
    def edit_rule(self, event=None):
        """双击编辑规则"""
        selection = self.rule_tree.selection()
        if not selection:
            return
        
        category = self.current_category_var.get()
        if not category:
            return
            
        item = self.rule_tree.item(selection[0])
        values = item['values']
        rule_name = values[0]
        rule_pattern = values[2]
        
        # 创建编辑对话框
        self.show_rule_edit_dialog(category, rule_name, rule_pattern)
    
    def show_rule_edit_dialog(self, category, rule_name, rule_pattern):
        """显示规则编辑对话框"""
        dialog = tk.Toplevel(self.window)
        dialog.title("编辑规则")
        dialog.geometry("500x200")
        dialog.transient(self.window)
        dialog.grab_set()
        
        # 居中显示
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # 规则名称
        ttk.Label(dialog, text="规则名称:").pack(anchor=tk.W, padx=10, pady=(10, 5))
        name_var = tk.StringVar(value=rule_name)
        name_entry = ttk.Entry(dialog, textvariable=name_var)
        name_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # 正则表达式
        ttk.Label(dialog, text="正则表达式:").pack(anchor=tk.W, padx=10, pady=(0, 5))
        pattern_var = tk.StringVar(value=rule_pattern)
        pattern_entry = ttk.Entry(dialog, textvariable=pattern_var)
        pattern_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # 按钮
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def save_changes():
            new_name = name_var.get().strip()
            new_pattern = pattern_var.get().strip()
            
            if not new_name or not new_pattern:
                messagebox.showwarning("警告", "规则名称和正则表达式不能为空")
                return
            
            # 找到并更新规则
            rules_list = self.rules[category]['rules']
            for rule in rules_list:
                if rule['name'] == rule_name:
                    rule['name'] = new_name
                    rule['pattern'] = new_pattern
                    break
            
            self.refresh_rules(category)
            dialog.destroy()
        
        ttk.Button(btn_frame, text="保存", command=save_changes).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def toggle_rule(self):
        """切换规则启用状态"""
        selection = self.rule_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个规则")
            return
        
        category = self.current_category_var.get()
        if not category or category not in self.rules:
            messagebox.showwarning("警告", "请先选择一个有效的分类")
            return
            
        item = self.rule_tree.item(selection[0])
        rule_name = item['values'][1]  # 规则名称在第二列
        rule_pattern = item['values'][2]  # 正则表达式在第三列
        
        try:
            # 处理不同的规则数据格式
            if isinstance(self.rules[category], dict):
                rules_list = self.rules[category].get('rules', [])
            else:
                rules_list = self.rules[category]
            
            # 找到并切换规则状态
            rule_found = False
            for i, rule in enumerate(rules_list):
                if isinstance(rule, dict):
                    # 新格式：字典包含name, pattern, enabled
                    if rule.get('name') == rule_name or rule.get('pattern') == rule_pattern:
                        rule['enabled'] = not rule.get('enabled', True)
                        rule_found = True
                        break
                else:
                    # 旧格式：直接是正则表达式字符串，需要转换
                    if rule == rule_pattern:
                        # 转换为新格式
                        new_rule = {
                            'name': rule_name,
                            'pattern': rule,
                            'enabled': False  # 切换为禁用
                        }
                        rules_list[i] = new_rule
                        rule_found = True
                        break
            
            if rule_found:
                self.refresh_rules(category)
            else:
                messagebox.showwarning("警告", "未找到指定的规则")
                
        except Exception as e:
            messagebox.showerror("错误", f"切换规则状态失败: {str(e)}")
    
    def toggle_category(self):
        """切换分类启用状态"""
        selection = self.category_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个分类")
            return
            
        item = self.category_tree.item(selection[0])
        category = item['values'][1]  # 修正索引，分类名称在第二列
        
        # 处理不同的规则数据格式
        if isinstance(self.rules[category], dict):
            # 如果已经是字典格式
            current_enabled = self.rules[category].get('enabled', True)
            self.rules[category]['enabled'] = not current_enabled
        else:
            # 如果是列表格式，转换为字典格式
            rules_list = self.rules[category]
            self.rules[category] = {
                'enabled': False,  # 切换为禁用
                'rules': rules_list
            }
        
        self.refresh_categories()
        if self.current_category_var.get() == category:
            self.refresh_rules(category)
    
    def select_all_categories(self):
        """启用所有分类"""
        for category in self.rules.keys():
            if isinstance(self.rules[category], dict):
                self.rules[category]['enabled'] = True
            else:
                # 转换为字典格式
                rules_list = self.rules[category]
                self.rules[category] = {
                    'enabled': True,
                    'rules': rules_list
                }
        self.refresh_categories()
    
    def deselect_all_categories(self):
        """禁用所有分类"""
        for category in self.rules.keys():
            if isinstance(self.rules[category], dict):
                self.rules[category]['enabled'] = False
            else:
                # 转换为字典格式
                rules_list = self.rules[category]
                self.rules[category] = {
                    'enabled': False,
                    'rules': rules_list
                }
        self.refresh_categories()
    
    def add_rule_dialog(self):
        """打开添加规则对话框"""
        current_category = self.current_category_var.get()
        if not current_category:
            messagebox.showwarning("警告", "请先选择一个分类")
            return
        
        # 创建弹窗
        dialog = AddRuleDialog(self.window, current_category, self.add_rule_callback)
    
    def add_rule_callback(self, category, name, pattern):
        """添加规则的回调函数"""
        try:
            # 验证正则表达式
            import re
            re.compile(pattern)
            
            # 获取或创建分类的规则列表
            if isinstance(self.rules[category], dict):
                if 'rules' not in self.rules[category]:
                    self.rules[category]['rules'] = []
                rules_list = self.rules[category]['rules']
            else:
                rules_list = self.rules[category]
            
            # 添加新规则（使用字典格式存储名称和模式）
            new_rule = {
                'name': name,
                'pattern': pattern,
                'enabled': True
            }
            
            rules_list.append(new_rule)
            
            # 刷新显示
            self.refresh_rules(category)
            messagebox.showinfo("成功", f"已添加规则: {name}")
            
        except re.error as e:
            messagebox.showerror("错误", f"无效的正则表达式: {str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"添加规则失败: {str(e)}")
    
    def save_rules(self):
        """保存规则"""
        self.save_callback()
        messagebox.showinfo("成功", "规则已保存")
        self.window.destroy()
    
    def restore_defaults(self):
        """恢复默认规则"""
        if messagebox.askyesno("确认", "确定要恢复默认规则吗？这将覆盖所有自定义规则。"):
            # 这里需要访问默认规则
            default_rules = {
                "API接口": [
                    r"/api/[^'\"\\s]+",
                    r"\.get\(['\"]([^'\"]+)['\"]",
                    r"\.post\(['\"]([^'\"]+)['\"]",
                    r"method:\s*['\"]get['\"]",
                    r"method:\s*['\"]post['\"]"
                ],
                "密钥信息": [
                    r"api[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
                    r"secret[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
                    r"access[_-]?token['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
                    r"private[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]"
                ],
                "邮箱信息": [
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                ],
                "手机号": [
                    r"1[3-9]\d{9}",
                    r"\+86\s*1[3-9]\d{9}"
                ],
                "IP地址": [
                    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
                ],
                "数据库连接": [
                    r"jdbc:[^'\"\\s]+",
                    r"mongodb://[^'\"\\s]+",
                    r"mysql://[^'\"\\s]+",
                    r"postgresql://[^'\"\\s]+"
                ],
                "云服务配置": [
                    r"AKIA[0-9A-Z]{16}",
                    r"aws_secret_access_key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9/+=]{40})['\"]",
                    r"aliyun[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]"
                ]
            }
            
            self.rules.clear()
            self.rules.update(default_rules)
            self.refresh_categories()
            # 清空当前分类选择
            self.current_category_var.set("")
            # 清空规则列表
            for item in self.rule_tree.get_children():
                self.rule_tree.delete(item)
    
    def import_yaml_rules(self):
        """导入YAML规则文件"""
        file_path = filedialog.askopenfilename(
            title="选择YAML规则文件",
            filetypes=[("YAML文件", "*.yml *.yaml"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_data = yaml.safe_load(f)
                
                # 解析YAML格式并转换为程序使用的格式
                imported_rules = {}
                
                for group_data in yaml_data:
                    group_name = group_data.get('group', '未分类')
                    rules_list = group_data.get('rules', [])
                    
                    if group_name not in imported_rules:
                        imported_rules[group_name] = []
                    
                    for rule in rules_list:
                        # 只导入启用的规则
                        if rule.get('loaded', True):
                            regex = rule.get('regex', '')
                            if regex:
                                imported_rules[group_name].append(regex)
                
                # 询问是否合并或替换现有规则
                choice = messagebox.askyesnocancel(
                    "导入规则",
                    f"成功解析YAML文件，共找到 {len(imported_rules)} 个分类。\n\n"
                    f"点击'是'合并到现有规则\n"
                    f"点击'否'替换所有现有规则\n"
                    f"点击'取消'放弃导入"
                )
                
                if choice is True:  # 合并
                    for category, patterns in imported_rules.items():
                        if category in self.rules:
                            # 避免重复规则
                            existing_patterns = set(self.rules[category])
                            new_patterns = [p for p in patterns if p not in existing_patterns]
                            self.rules[category].extend(new_patterns)
                        else:
                            self.rules[category] = patterns
                    messagebox.showinfo("成功", f"已合并导入 {len(imported_rules)} 个分类的规则")
                    
                elif choice is False:  # 替换
                    self.rules.clear()
                    self.rules.update(imported_rules)
                    messagebox.showinfo("成功", f"已替换导入 {len(imported_rules)} 个分类的规则")
                
                if choice is not None:
                    self.refresh_categories()
                    
            except yaml.YAMLError as e:
                messagebox.showerror("错误", f"YAML文件格式错误: {str(e)}")
            except Exception as e:
                messagebox.showerror("错误", f"导入失败: {str(e)}")


class AddRuleDialog:
    def __init__(self, parent, category, callback):
        self.category = category
        self.callback = callback
        
        self.window = tk.Toplevel(parent)
        self.window.title("添加新规则")
        self.window.transient(parent)
        self.window.grab_set()
        
        # 窗口居中显示
        self.center_window(500, 450)
        
        self.setup_gui()
    
    def center_window(self, width, height):
        """将窗口居中显示"""
        # 获取屏幕尺寸
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        # 计算居中位置
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.window.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_gui(self):
        """设置GUI界面"""
        # 主框架
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        ttk.Label(main_frame, text=f"为分类 '{self.category}' 添加新规则", font=('', 12, 'bold')).pack(anchor=tk.W, pady=(0, 20))
        
        # 规则名称
        ttk.Label(main_frame, text="规则名称:", font=('', 10)).pack(anchor=tk.W, pady=(0, 5))
        self.name_var = tk.StringVar()
        name_entry = ttk.Entry(main_frame, textvariable=self.name_var, font=('', 10))
        name_entry.pack(fill=tk.X, pady=(0, 15))
        name_entry.focus()  # 设置焦点
        
        # 正则表达式
        ttk.Label(main_frame, text="正则表达式:", font=('', 10)).pack(anchor=tk.W, pady=(0, 5))
        self.pattern_var = tk.StringVar()
        pattern_entry = ttk.Entry(main_frame, textvariable=self.pattern_var, font=('', 10))
        pattern_entry.pack(fill=tk.X, pady=(0, 10))
        
        # 示例说明
        example_frame = ttk.LabelFrame(main_frame, text="示例", padding=10)
        example_frame.pack(fill=tk.X, pady=(0, 15))
        
        examples_text = """常用正则表达式示例：
• 邮箱地址: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}
• 手机号码: 1[3-9]\\d{9}
• IP地址: (?:[0-9]{1,3}\\.){3}[0-9]{1,3}
• API密钥: api[_-]?key['"\\"]?\\s*[:=]\\s*['"\\"]([a-zA-Z0-9_-]{16,})['"\\"]
• URL路径: /api/[^'"\\\\s]+"""
        
        ttk.Label(example_frame, text=examples_text, font=('', 9), foreground='gray').pack(anchor=tk.W)
        
        # 分隔线
        separator = ttk.Separator(main_frame, orient='horizontal')
        separator.pack(fill=tk.X, pady=(30, 20))
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 左侧测试按钮
        test_btn = ttk.Button(button_frame, text="测试正则", command=self.test_regex, width=15)
        test_btn.pack(side=tk.LEFT)
        
        # 右侧操作按钮
        right_buttons = ttk.Frame(button_frame)
        right_buttons.pack(side=tk.RIGHT)
        
        cancel_btn = ttk.Button(right_buttons, text="取消", command=self.window.destroy, width=12)
        cancel_btn.pack(side=tk.LEFT, padx=(0, 15))
        
        # 添加按钮使用不同样式，更醒目
        add_btn = ttk.Button(right_buttons, text="确定添加", command=self.add_rule, width=15)
        add_btn.pack(side=tk.LEFT)
        
        # 添加一个更醒目的底部确定按钮
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=(20, 0))
        
        confirm_btn = ttk.Button(bottom_frame, text="确定", command=self.add_rule, width=20)
        confirm_btn.pack(anchor=tk.CENTER)
        
        # 设置添加按钮的样式（如果可能）
        try:
            add_btn.configure(style='Accent.TButton')
        except:
            pass  # 如果样式不支持就忽略
        
        # 设置添加按钮为默认按钮（回车键触发）
        self.window.bind('<Return>', lambda e: self.add_rule())
        
        # 绑定Tab键切换焦点
        name_entry.bind('<Return>', lambda e: pattern_entry.focus())
        # 在正则表达式输入框按回车直接添加规则
        pattern_entry.bind('<Return>', lambda e: self.add_rule())
    
    def test_regex(self):
        """测试正则表达式"""
        pattern = self.pattern_var.get().strip()
        if not pattern:
            messagebox.showwarning("警告", "请输入正则表达式")
            return
        
        try:
            re.compile(pattern)
            messagebox.showinfo("测试结果", "正则表达式语法正确！")
        except re.error as e:
            messagebox.showerror("测试结果", f"正则表达式语法错误:\n{str(e)}")
    
    def add_rule(self):
        """添加规则"""
        name = self.name_var.get().strip()
        pattern = self.pattern_var.get().strip()
        
        if not name:
            messagebox.showwarning("警告", "请输入规则名称")
            return
        
        if not pattern:
            messagebox.showwarning("警告", "请输入正则表达式")
            return
        
        # 验证正则表达式
        try:
            re.compile(pattern)
        except re.error as e:
            messagebox.showerror("错误", f"无效的正则表达式:\n{str(e)}")
            return
        
        # 调用回调函数
        self.callback(self.category, name, pattern)
        self.window.destroy()


class ExportFormatWindow:
    def __init__(self, parent, scan_results):
        self.scan_results = scan_results
        
        self.window = tk.Toplevel(parent)
        self.window.title("导出格式选择")
        self.window.transient(parent)
        self.window.grab_set()
        
        # 窗口居中显示
        self.center_window(400, 250)
        
        self.setup_gui()
    
    def center_window(self, width, height):
        """将窗口居中显示"""
        # 获取屏幕尺寸
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        # 计算居中位置
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.window.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_gui(self):
        """设置GUI界面"""
        # 主框架
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        ttk.Label(main_frame, text="选择导出格式:", font=('', 12, 'bold')).pack(anchor=tk.W, pady=(0, 15))
        
        # 格式选择
        self.format_var = tk.StringVar(value="json")
        
        # JSON选项
        json_frame = ttk.Frame(main_frame)
        json_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(json_frame, text="JSON格式", variable=self.format_var, value="json").pack(side=tk.LEFT)
        ttk.Label(json_frame, text="- 保留完整数据结构，便于程序处理", font=('', 9)).pack(side=tk.LEFT, padx=(10, 0))
        
        # CSV选项
        csv_frame = ttk.Frame(main_frame)
        csv_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(csv_frame, text="CSV格式", variable=self.format_var, value="csv").pack(side=tk.LEFT)
        ttk.Label(csv_frame, text="- 表格格式，便于Excel等软件打开", font=('', 9)).pack(side=tk.LEFT, padx=(10, 0))
        
        # 统计信息
        total_results = len(self.scan_results)
        stats_text = f"共 {total_results} 条扫描结果"
        ttk.Label(main_frame, text=stats_text, font=('', 10), foreground='gray').pack(anchor=tk.W, pady=(15, 0))
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(button_frame, text="导出", command=self.export_data).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="取消", command=self.window.destroy).pack(side=tk.RIGHT)
    
    def export_data(self):
        """执行导出"""
        format_type = self.format_var.get()
        
        if format_type == "json":
            file_path = filedialog.asksaveasfilename(
                title="保存JSON文件",
                defaultextension=".json",
                filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
            )
            if file_path:
                self.export_json(file_path)
        else:
            file_path = filedialog.asksaveasfilename(
                title="保存CSV文件",
                defaultextension=".csv",
                filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")]
            )
            if file_path:
                self.export_csv(file_path)
    
    def export_json(self, file_path):
        """导出JSON格式"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("导出成功", f"JSON文件已保存到:\n{file_path}")
            self.window.destroy()
        except Exception as e:
            messagebox.showerror("导出失败", f"JSON导出失败:\n{str(e)}")
    
    def export_csv(self, file_path):
        """导出CSV格式"""
        try:
            import csv
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:  # 使用utf-8-sig以支持Excel
                writer = csv.writer(f)
                # 写入表头
                writer.writerow(['文件路径', '行号', '敏感信息类型', '匹配内容', '完整行内容', '文件大小'])
                
                # 写入数据
                for result in self.scan_results:
                    writer.writerow([
                        result.get('file', ''),
                        result.get('line', ''),
                        result.get('category', ''),
                        result.get('content', ''),
                        result.get('full_line', '').replace('\n', ' ').replace('\r', ''),  # 移除换行符
                        result.get('file_size', '')
                    ])
            
            messagebox.showinfo("导出成功", f"CSV文件已保存到:\n{file_path}\n\n可使用Excel等软件打开查看")
            self.window.destroy()
        except Exception as e:
            messagebox.showerror("导出失败", f"CSV导出失败:\n{str(e)}")


class FileTypeSelectorWindow:
    def __init__(self, parent, file_types_var, main_window=None):
        self.file_types_var = file_types_var
        self.main_window = main_window
        
        self.window = tk.Toplevel(parent)
        self.window.title("文件类型选择")
        self.window.transient(parent)
        self.window.grab_set()
        
        # 窗口居中显示
        self.center_window()
        
        # 常见文件类型
        self.file_types = {
            "Web前端": {
                "*.js": "JavaScript文件",
                "*.jsx": "React JSX文件", 
                "*.ts": "TypeScript文件",
                "*.tsx": "TypeScript JSX文件",
                "*.vue": "Vue组件文件",
                "*.html": "HTML文件",
                "*.htm": "HTML文件",
                "*.css": "CSS样式文件",
                "*.scss": "SCSS样式文件",
                "*.sass": "SASS样式文件",
                "*.less": "LESS样式文件"
            },
            "配置文件": {
                "*.json": "JSON配置文件",
                "*.xml": "XML配置文件",
                "*.yml": "YAML配置文件",
                "*.yaml": "YAML配置文件",
                "*.ini": "INI配置文件",
                "*.conf": "配置文件",
                "*.config": "配置文件"
            },
            "后端代码": {
                "*.py": "Python文件",
                "*.java": "Java文件",
                "*.php": "PHP文件",
                "*.asp": "ASP文件",
                "*.aspx": "ASPX文件",
                "*.jsp": "JSP文件",
                "*.go": "Go语言文件",
                "*.rb": "Ruby文件",
                "*.cs": "C#文件"
            },
            "文档文件": {
                "*.txt": "文本文件",
                "*.md": "Markdown文件",
                "*.log": "日志文件",
                "*.sql": "SQL文件"
            },
            "其他": {
                "*.sh": "Shell脚本",
                "*.bat": "批处理文件",
                "*.ps1": "PowerShell脚本",
                "*.dockerfile": "Docker文件",
                "*.env": "环境变量文件"
            }
        }
        
        self.setup_gui()
        
        # 根据当前选择初始化复选框状态
        self.init_selections()
        
        # 初始化自定义类型显示
        self.update_custom_types_display()
    
    def center_window(self):
        """将窗口居中显示"""
        width = 650
        height = 500
        
        # 获取屏幕尺寸
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        # 计算居中位置
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.window.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_gui(self):
        """设置GUI界面"""
        # 主框架
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 说明标签
        ttk.Label(main_frame, text="选择要扫描的文件类型:", font=('', 10, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        
        # 创建滚动框架容器
        scroll_container = ttk.Frame(main_frame)
        scroll_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 创建滚动框架
        canvas = tk.Canvas(scroll_container)
        scrollbar = ttk.Scrollbar(scroll_container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # 绑定canvas尺寸变化事件，让内容框架自适应宽度
        def on_canvas_configure(event):
            canvas.itemconfig(canvas.find_all()[0], width=event.width)
        canvas.bind('<Configure>', on_canvas_configure)
        
        # 绑定鼠标滚轮事件
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        # 绑定滚轮事件到canvas和scrollable_frame
        canvas.bind("<MouseWheel>", on_mousewheel)
        self.scrollable_frame.bind("<MouseWheel>", on_mousewheel)
        
        # 递归绑定所有子控件的滚轮事件
        def bind_mousewheel_to_children(widget):
            widget.bind("<MouseWheel>", on_mousewheel)
            for child in widget.winfo_children():
                bind_mousewheel_to_children(child)
        
        # 延迟绑定，确保所有控件都创建完成
        self.window.after(100, lambda: bind_mousewheel_to_children(self.scrollable_frame))
        
        # 存储复选框变量
        self.type_vars = {}
        
        # 创建分类和复选框
        for category, types in self.file_types.items():
            # 分类标题
            category_frame = ttk.LabelFrame(self.scrollable_frame, text=category, padding=10)
            category_frame.pack(fill=tk.X, pady=(0, 10))
            
            # 文件类型复选框 - 使用网格布局以节省空间
            row = 0
            col = 0
            max_cols = 2  # 每行最多2个复选框
            
            for file_type, description in types.items():
                var = tk.BooleanVar()
                self.type_vars[file_type] = var
                
                checkbox = ttk.Checkbutton(
                    category_frame,
                    text=f"{file_type} - {description}",
                    variable=var
                )
                checkbox.grid(row=row, column=col, sticky='w', padx=5, pady=2)
                
                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
        
        # 使用pack布局，让内容占满整个空间
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 自定义文件类型区域
        custom_section = ttk.LabelFrame(main_frame, text="自定义文件类型", padding=10)
        custom_section.pack(fill=tk.X, pady=(5, 10))
        
        # 输入框和添加按钮
        input_frame = ttk.Frame(custom_section)
        input_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(input_frame, text="文件后缀:").pack(side=tk.LEFT)
        self.custom_type_var = tk.StringVar()
        custom_entry = ttk.Entry(input_frame, textvariable=self.custom_type_var, width=15)
        custom_entry.pack(side=tk.LEFT, padx=(5, 0))
        ttk.Label(input_frame, text="(例: *.log, *.conf)", font=('', 8)).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(input_frame, text="添加", command=self.add_custom_type).pack(side=tk.LEFT, padx=(5, 0))
        
        # 已添加的自定义类型列表
        list_frame = ttk.Frame(custom_section)
        list_frame.pack(fill=tk.X)
        
        ttk.Label(list_frame, text="已添加的自定义类型:", font=('', 9)).pack(anchor=tk.W)
        
        # 创建滚动的自定义类型列表
        self.custom_list_frame = ttk.Frame(list_frame)
        self.custom_list_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 存储自定义类型
        self.custom_types = []
        
        # 底部按钮
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # 左侧按钮
        left_buttons = ttk.Frame(button_frame)
        left_buttons.pack(side=tk.LEFT)
        
        ttk.Button(left_buttons, text="全选", command=self.select_all).pack(side=tk.LEFT)
        ttk.Button(left_buttons, text="取消全选", command=self.deselect_all).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(left_buttons, text="默认配置", command=self.load_default_config).pack(side=tk.LEFT, padx=(5, 0))
        
        # 右侧按钮
        right_buttons = ttk.Frame(button_frame)
        right_buttons.pack(side=tk.RIGHT)
        
        ttk.Button(right_buttons, text="取消", command=self.window.destroy).pack(side=tk.LEFT)
        ttk.Button(right_buttons, text="确定", command=self.apply_selection).pack(side=tk.LEFT, padx=(5, 0))
    
    def init_selections(self):
        """根据当前选择初始化复选框状态"""
        current_types = [t.strip() for t in self.file_types_var.get().split(',')]
        
        for file_type, var in self.type_vars.items():
            var.set(file_type in current_types)
    

    
    def select_all(self):
        """选择所有文件类型"""
        for var in self.type_vars.values():
            var.set(True)
    
    def deselect_all(self):
        """取消选择所有文件类型"""
        for var in self.type_vars.values():
            var.set(False)
    
    def add_custom_type(self):
        """添加自定义文件类型"""
        custom_type = self.custom_type_var.get().strip()
        if not custom_type:
            messagebox.showwarning("警告", "请输入文件类型")
            return
        
        # 确保格式正确
        if not custom_type.startswith('*.'):
            custom_type = '*.' + custom_type.lstrip('*.')
        
        # 检查是否已存在
        if custom_type in self.custom_types or custom_type in self.type_vars:
            messagebox.showinfo("提示", "该文件类型已存在")
            return
        
        # 添加到自定义类型列表
        self.custom_types.append(custom_type)
        
        # 添加到类型变量字典
        var = tk.BooleanVar(value=True)  # 默认选中
        self.type_vars[custom_type] = var
        
        # 更新自定义类型显示
        self.update_custom_types_display()
        
        # 清空输入框
        self.custom_type_var.set("")
    
    def update_custom_types_display(self):
        """更新自定义类型显示"""
        # 清空现有显示
        for widget in self.custom_list_frame.winfo_children():
            widget.destroy()
        
        # 显示所有自定义类型
        for i, custom_type in enumerate(self.custom_types):
            type_frame = ttk.Frame(self.custom_list_frame)
            type_frame.pack(fill=tk.X, pady=1)
            
            # 复选框
            var = self.type_vars[custom_type]
            checkbox = ttk.Checkbutton(type_frame, text=custom_type, variable=var)
            checkbox.pack(side=tk.LEFT)
            
            # 删除按钮
            delete_btn = ttk.Button(
                type_frame, 
                text="删除", 
                width=6,
                command=lambda ct=custom_type: self.remove_custom_type(ct)
            )
            delete_btn.pack(side=tk.RIGHT)
    
    def remove_custom_type(self, custom_type):
        """删除自定义文件类型"""
        if messagebox.askyesno("确认删除", f"确定要删除文件类型 '{custom_type}' 吗？"):
            # 从列表中移除
            if custom_type in self.custom_types:
                self.custom_types.remove(custom_type)
            
            # 从变量字典中移除
            if custom_type in self.type_vars:
                del self.type_vars[custom_type]
            
            # 更新显示
            self.update_custom_types_display()
    
    def load_default_config(self):
        """加载默认配置"""
        if messagebox.askyesno("加载默认配置", "确定要加载默认配置吗？这将重置所有选择。"):
            # 默认选中的文件类型
            default_types = [
                "*.js", "*.jsx", "*.ts", "*.tsx", "*.vue", 
                "*.html", "*.css", "*.json", "*.xml"
            ]
            
            # 重置所有选择
            for file_type, var in self.type_vars.items():
                var.set(file_type in default_types)
            
            # 清空自定义类型
            self.custom_types.clear()
            # 移除自定义类型的变量
            custom_to_remove = [ft for ft in self.type_vars.keys() if ft not in self.get_all_predefined_types()]
            for ct in custom_to_remove:
                del self.type_vars[ct]
            
            # 更新显示
            self.update_custom_types_display()
    
    def get_all_predefined_types(self):
        """获取所有预定义的文件类型"""
        all_types = set()
        for category_types in self.file_types.values():
            all_types.update(category_types.keys())
        return all_types
    
    def recreate_type_checkboxes(self):
        """重新创建文件类型复选框"""
        # 清除现有复选框
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        # 重新创建
        self.type_vars = {}
        
        # 创建分类和复选框
        for category, types in self.file_types.items():
            # 分类标题
            category_frame = ttk.LabelFrame(self.scrollable_frame, text=category, padding=10)
            category_frame.pack(fill=tk.X, pady=(0, 10))
            
            # 文件类型复选框 - 使用网格布局以节省空间
            row = 0
            col = 0
            max_cols = 2  # 每行最多2个复选框
            
            for file_type, description in types.items():
                var = tk.BooleanVar()
                self.type_vars[file_type] = var
                
                checkbox = ttk.Checkbutton(
                    category_frame,
                    text=f"{file_type} - {description}",
                    variable=var
                )
                checkbox.grid(row=row, column=col, sticky='w', padx=5, pady=2)
                
                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
    
    def apply_selection(self):
        """应用选择"""
        selected_types = []
        for file_type, var in self.type_vars.items():
            if var.get():
                selected_types.append(file_type)
        
        if selected_types:
            self.file_types_var.set(','.join(selected_types))
            
            # 如果有主窗口引用，触发结果过滤
            if self.main_window and hasattr(self.main_window, 'filter_results_by_file_type'):
                self.main_window.filter_results_by_file_type(selected_types)
            
            self.window.destroy()
        else:
            messagebox.showwarning("警告", "请至少选择一种文件类型")


class WebpackToolWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Webpack反编译工具")
        self.window.transient(parent)
        
        # 窗口居中显示
        self.center_window(700, 500)
        
        self.setup_gui()
    
    def center_window(self, width, height):
        """将窗口居中显示"""
        # 获取屏幕尺寸
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        # 计算居中位置
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.window.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_gui(self):
        """设置Webpack工具界面"""
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 说明文本
        info_text = """Webpack反编译工具

此工具集成了Packer-Fuzzer的功能，用于分析webpack打包的网站。

功能包括：
1. 检测网站是否使用webpack打包
2. 提取和分析JavaScript文件
3. 查找敏感信息和API接口
4. 源码映射文件(.map)分析

使用方法：
1. 输入目标网站URL
2. 点击"开始分析"
3. 查看分析结果
"""
        
        info_label = ttk.Label(main_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor=tk.W, pady=(0, 10))
        
        # URL输入
        url_frame = ttk.LabelFrame(main_frame, text="目标网站", padding=10)
        url_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(url_frame, text="URL:").pack(side=tk.LEFT)
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(url_frame, textvariable=self.url_var, width=50)
        url_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        
        ttk.Button(url_frame, text="开始分析", command=self.start_analysis).pack(side=tk.RIGHT)
        
        # 结果显示
        result_frame = ttk.LabelFrame(main_frame, text="分析结果", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # 底部按钮
        bottom_frame = ttk.Frame(self.window)
        bottom_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(bottom_frame, text="清空结果", command=self.clear_results).pack(side=tk.LEFT)
        ttk.Button(bottom_frame, text="保存结果", command=self.save_results).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(bottom_frame, text="关闭", command=self.window.destroy).pack(side=tk.RIGHT)
    
    def start_analysis(self):
        """开始分析"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("警告", "请输入目标URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_var.set(url)
        
        self.result_text.insert(tk.END, f"开始分析: {url}\n")
        self.result_text.insert(tk.END, "=" * 50 + "\n\n")
        
        # 使用真正的分析功能
        self.real_analysis(url)
    
    def real_analysis(self, url):
        """真正的分析功能"""
        def analysis_thread():
            try:
                # 获取父窗口的packer_fuzzer实例
                parent_app = None
                for widget in self.window.winfo_toplevel().winfo_children():
                    if hasattr(widget, 'packer_fuzzer'):
                        parent_app = widget
                        break
                
                if parent_app and hasattr(parent_app, 'packer_fuzzer'):
                    packer_fuzzer = parent_app.packer_fuzzer
                else:
                    from scanner_engine import PackerFuzzerIntegration
                    packer_fuzzer = PackerFuzzerIntegration()
                
                def update_callback(message):
                    self.result_text.insert(tk.END, f"{message}\n")
                    self.result_text.see(tk.END)
                    self.window.update()
                
                # 执行分析
                result = packer_fuzzer.analyze_website(url, update_callback)
                
                # 显示格式化结果
                formatted_result = packer_fuzzer.format_results(result)
                self.result_text.insert(tk.END, "\n" + formatted_result)
                self.result_text.see(tk.END)
                
            except Exception as e:
                self.result_text.insert(tk.END, f"分析出错: {str(e)}\n")
        
        # 启动分析线程
        threading.Thread(target=analysis_thread, daemon=True).start()
    
    def simulate_analysis(self, url):
        """模拟分析过程（实际实现中会集成真正的Packer-Fuzzer功能）"""
        import time
        import random
        
        def analysis_thread():
            try:
                # 模拟分析步骤
                steps = [
                    "正在检测网站技术栈...",
                    "正在下载JavaScript文件...",
                    "正在分析webpack配置...",
                    "正在提取API接口...",
                    "正在查找敏感信息...",
                    "分析完成！"
                ]
                
                for step in steps:
                    self.result_text.insert(tk.END, f"{step}\n")
                    self.result_text.see(tk.END)
                    self.window.update()
                    time.sleep(1)
                
                # 模拟发现的内容
                findings = [
                    "发现webpack打包特征",
                    "找到3个JavaScript文件",
                    "提取到15个API接口",
                    "发现2个可能的敏感信息",
                    "检测到source map文件"
                ]
                
                self.result_text.insert(tk.END, "\n发现的内容:\n")
                for finding in findings:
                    self.result_text.insert(tk.END, f"✓ {finding}\n")
                
                self.result_text.insert(tk.END, "\n详细信息:\n")
                self.result_text.insert(tk.END, "API接口:\n")
                for i in range(5):
                    self.result_text.insert(tk.END, f"  - /api/user/{i+1}\n")
                    self.result_text.insert(tk.END, f"  - /api/data/get_{i+1}\n")
                
                self.result_text.insert(tk.END, "\n敏感信息:\n")
                self.result_text.insert(tk.END, "  - 可能的API密钥: ak_xxxxxxxxxxxxxxxx\n")
                self.result_text.insert(tk.END, "  - 数据库连接字符串片段\n")
                
                self.result_text.insert(tk.END, "\n" + "=" * 50 + "\n")
                self.result_text.see(tk.END)
                
            except Exception as e:
                self.result_text.insert(tk.END, f"分析出错: {str(e)}\n")
        
        # 启动分析线程
        threading.Thread(target=analysis_thread, daemon=True).start()
    
    def clear_results(self):
        """清空结果"""
        self.result_text.delete(1.0, tk.END)
    
    def save_results(self):
        """保存结果"""
        content = self.result_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("警告", "没有可保存的内容")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("成功", f"结果已保存到: {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {str(e)}")


if __name__ == "__main__":
    app = SensitiveInfoScanner()
    app.run()
