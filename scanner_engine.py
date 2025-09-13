import os
import re
import threading
import queue
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import mimetypes
from typing import List, Dict, Tuple, Optional


class FileScanner:
    """多线程文件扫描引擎"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.is_scanning = False
        self.scanned_files = 0
        self.total_files = 0
        self.results = []
        self.progress_callback = None
        self.result_callback = None
        
    def set_progress_callback(self, callback):
        """设置进度回调函数"""
        self.progress_callback = callback
        
    def set_result_callback(self, callback):
        """设置结果回调函数"""
        self.result_callback = callback
    
    def get_file_list(self, folder_path: str, file_patterns: List[str]) -> List[Path]:
        """获取要扫描的文件列表"""
        files_to_scan = []
        
        try:
            folder_path = Path(folder_path)
            for pattern in file_patterns:
                files_to_scan.extend(folder_path.rglob(pattern.strip()))
        except Exception as e:
            print(f"获取文件列表时出错: {str(e)}")
        
        # 去重并过滤
        unique_files = []
        seen = set()
        
        for file_path in files_to_scan:
            if file_path.is_file() and str(file_path) not in seen:
                # 检查文件大小（跳过过大的文件）
                try:
                    if file_path.stat().st_size > 50 * 1024 * 1024:  # 50MB
                        continue
                except:
                    continue
                    
                unique_files.append(file_path)
                seen.add(str(file_path))
        
        return unique_files
    
    def scan_single_file(self, file_path: Path, rules: Dict[str, List[str]], base_path: str) -> List[Dict]:
        """扫描单个文件"""
        results = []
        
        try:
            # 检测文件编码
            encoding = self.detect_encoding(file_path)
            if not encoding:
                return results
            
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                lines = f.readlines()
            
            relative_path = os.path.relpath(str(file_path), base_path)
            
            for line_num, line in enumerate(lines, 1):
                if not self.is_scanning:
                    break
                
                # 跳过过长的行（可能是压缩文件）
                if len(line) > 10000:
                    continue
                
                for category, patterns in rules.items():
                    for pattern in patterns:
                        try:
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                result = {
                                    'file': relative_path,
                                    'line': line_num,
                                    'category': category,
                                    'content': match.group().strip(),
                                    'pattern': pattern,
                                    'full_line': line.strip(),
                                    'full_path': str(file_path),
                                    'file_size': file_path.stat().st_size,
                                    'file_type': mimetypes.guess_type(str(file_path))[0] or 'unknown'
                                }
                                results.append(result)
                        except re.error:
                            continue
                        except Exception as e:
                            print(f"处理规则时出错: {str(e)}")
                            continue
                            
        except Exception as e:
            print(f"扫描文件 {file_path} 时出错: {str(e)}")
        
        return results
    
    def detect_encoding(self, file_path: Path) -> Optional[str]:
        """检测文件编码"""
        try:
            # 尝试常见编码
            encodings = ['utf-8', 'gbk', 'gb2312', 'utf-16', 'ascii', 'latin-1']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        f.read(1024)  # 读取前1024字符测试
                    return encoding
                except UnicodeDecodeError:
                    continue
                except Exception:
                    continue
            
            # 如果都失败了，尝试使用chardet检测
            try:
                import chardet
                with open(file_path, 'rb') as f:
                    raw_data = f.read(10240)  # 读取前10KB
                result = chardet.detect(raw_data)
                if result['confidence'] > 0.7:
                    return result['encoding']
            except:
                pass
                
        except Exception as e:
            print(f"检测文件编码时出错: {str(e)}")
        
        return None
    
    def scan_files(self, folder_path: str, file_patterns: List[str], rules: Dict[str, List[str]]):
        """主扫描函数"""
        self.is_scanning = True
        self.results.clear()
        self.scanned_files = 0
        
        try:
            # 获取文件列表
            files_to_scan = self.get_file_list(folder_path, file_patterns)
            self.total_files = len(files_to_scan)
            
            if self.total_files == 0:
                if self.progress_callback:
                    self.progress_callback("没有找到匹配的文件")
                return
            
            # 使用线程池扫描文件
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # 提交所有任务
                future_to_file = {
                    executor.submit(self.scan_single_file, file_path, rules, folder_path): file_path
                    for file_path in files_to_scan
                }
                
                # 处理完成的任务
                for future in as_completed(future_to_file):
                    if not self.is_scanning:
                        break
                    
                    file_path = future_to_file[future]
                    try:
                        file_results = future.result()
                        if file_results:
                            self.results.extend(file_results)
                            if self.result_callback:
                                for result in file_results:
                                    self.result_callback(result)
                        
                        self.scanned_files += 1
                        
                        # 更新进度
                        if self.progress_callback:
                            progress_text = f"已扫描 {self.scanned_files}/{self.total_files} 个文件"
                            self.progress_callback(progress_text)
                            
                    except Exception as e:
                        print(f"处理文件 {file_path} 的结果时出错: {str(e)}")
                        self.scanned_files += 1
            
            # 扫描完成
            if self.progress_callback:
                final_message = f"扫描完成！共扫描 {self.scanned_files} 个文件，发现 {len(self.results)} 个匹配项"
                self.progress_callback(final_message)
                
        except Exception as e:
            if self.progress_callback:
                self.progress_callback(f"扫描出错: {str(e)}")
        finally:
            self.is_scanning = False
    
    def stop_scan(self):
        """停止扫描"""
        self.is_scanning = False
    
    def get_results(self) -> List[Dict]:
        """获取扫描结果"""
        return self.results.copy()
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        stats = {}
        for result in self.results:
            category = result['category']
            stats[category] = stats.get(category, 0) + 1
        
        return {
            'total_files': self.total_files,
            'scanned_files': self.scanned_files,
            'total_matches': len(self.results),
            'categories': stats
        }


class WebpackAnalyzer:
    """Webpack分析器"""
    
    def __init__(self):
        self.webpack_indicators = [
            r'webpackJsonp',
            r'__webpack_require__',
            r'webpack:///',
            r'webpackChunkName',
            r'/\*\s*webpack\s*\*/',
            r'__webpack_exports__',
            r'__webpack_public_path__'
        ]
        
        self.sourcemap_patterns = [
            r'//# sourceMappingURL=(.+\.map)',
            r'//@ sourceMappingURL=(.+\.map)'
        ]
    
    def is_webpack_site(self, url: str) -> bool:
        """检测网站是否使用webpack"""
        try:
            import requests
            from bs4 import BeautifulSoup
            
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 检查HTML中的webpack特征
            html_indicators = [
                '<noscript>',
                'webpack',
                'chunk',
                'bundle'
            ]
            
            html_content = response.text.lower()
            for indicator in html_indicators:
                if indicator in html_content:
                    return True
            
            # 检查JavaScript文件
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script.get('src', '')
                if any(keyword in src.lower() for keyword in ['chunk', 'bundle', 'app', 'vendor']):
                    return True
            
            return False
            
        except Exception as e:
            print(f"检测webpack时出错: {str(e)}")
            return False
    
    def extract_js_files(self, url: str) -> List[str]:
        """提取JavaScript文件URL"""
        js_files = []
        
        try:
            import requests
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse
            
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 提取script标签中的src
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script.get('src', '')
                if src:
                    full_url = urljoin(url, src)
                    js_files.append(full_url)
            
            # 在页面内容中查找其他JS文件引用
            js_patterns = [
                r'"([^"]+\.js(?:\?[^"]*)?)"',
                r"'([^']+\.js(?:\?[^']*)?)'",
                r'src:\s*["\']([^"\']+\.js)["\']',
                r'import\s+["\']([^"\']+\.js)["\']'
            ]
            
            for pattern in js_patterns:
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    js_url = match.group(1)
                    full_url = urljoin(url, js_url)
                    if full_url not in js_files:
                        js_files.append(full_url)
            
        except Exception as e:
            print(f"提取JS文件时出错: {str(e)}")
        
        return js_files
    
    def analyze_js_file(self, js_url: str) -> Dict:
        """分析JavaScript文件"""
        result = {
            'url': js_url,
            'is_webpack': False,
            'has_sourcemap': False,
            'sourcemap_url': None,
            'apis': [],
            'sensitive_info': [],
            'size': 0
        }
        
        try:
            import requests
            
            response = requests.get(js_url, timeout=15)
            content = response.text
            result['size'] = len(content)
            
            # 检测webpack特征
            for indicator in self.webpack_indicators:
                if re.search(indicator, content):
                    result['is_webpack'] = True
                    break
            
            # 检测sourcemap
            for pattern in self.sourcemap_patterns:
                match = re.search(pattern, content)
                if match:
                    result['has_sourcemap'] = True
                    result['sourcemap_url'] = match.group(1)
                    break
            
            # 提取API接口
            api_patterns = [
                r'["\']([^"\']*\/api\/[^"\']*)["\']',
                r'["\']([^"\']*\/v\d+\/[^"\']*)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'endpoint:\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in api_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    api = match.group(1)
                    if api not in result['apis'] and len(api) > 3:
                        result['apis'].append(api)
            
            # 查找敏感信息
            sensitive_patterns = {
                'API密钥': [
                    r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']',
                    r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']'
                ],
                '访问令牌': [
                    r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']',
                    r'bearer["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']'
                ],
                '数据库连接': [
                    r'mongodb://[^"\'\\s]+',
                    r'mysql://[^"\'\\s]+',
                    r'postgresql://[^"\'\\s]+'
                ]
            }
            
            for category, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        result['sensitive_info'].append({
                            'category': category,
                            'content': match.group(),
                            'pattern': pattern
                        })
            
        except Exception as e:
            print(f"分析JS文件时出错: {str(e)}")
        
        return result
    
    def download_sourcemap(self, sourcemap_url: str, base_url: str) -> Optional[str]:
        """下载sourcemap文件"""
        try:
            import requests
            from urllib.parse import urljoin
            
            if not sourcemap_url.startswith('http'):
                sourcemap_url = urljoin(base_url, sourcemap_url)
            
            response = requests.get(sourcemap_url, timeout=10)
            if response.status_code == 200:
                return response.text
                
        except Exception as e:
            print(f"下载sourcemap文件时出错: {str(e)}")
        
        return None


class PackerFuzzerIntegration:
    """Packer-Fuzzer集成类"""
    
    def __init__(self):
        self.analyzer = WebpackAnalyzer()
    
    def analyze_website(self, url: str, callback=None) -> Dict:
        """分析网站"""
        result = {
            'url': url,
            'is_webpack': False,
            'js_files': [],
            'analysis_results': [],
            'total_apis': 0,
            'total_sensitive': 0,
            'errors': []
        }
        
        try:
            if callback:
                callback("正在检测网站技术栈...")
            
            # 检测是否为webpack站点
            result['is_webpack'] = self.analyzer.is_webpack_site(url)
            
            if callback:
                callback("正在提取JavaScript文件...")
            
            # 提取JS文件
            result['js_files'] = self.analyzer.extract_js_files(url)
            
            if callback:
                callback(f"找到 {len(result['js_files'])} 个JavaScript文件，开始分析...")
            
            # 分析每个JS文件
            for i, js_url in enumerate(result['js_files']):
                try:
                    if callback:
                        callback(f"正在分析文件 {i+1}/{len(result['js_files'])}: {js_url}")
                    
                    analysis = self.analyzer.analyze_js_file(js_url)
                    result['analysis_results'].append(analysis)
                    
                    result['total_apis'] += len(analysis['apis'])
                    result['total_sensitive'] += len(analysis['sensitive_info'])
                    
                except Exception as e:
                    error_msg = f"分析文件 {js_url} 时出错: {str(e)}"
                    result['errors'].append(error_msg)
                    if callback:
                        callback(error_msg)
            
            if callback:
                callback("分析完成！")
            
        except Exception as e:
            error_msg = f"分析网站时出错: {str(e)}"
            result['errors'].append(error_msg)
            if callback:
                callback(error_msg)
        
        return result
    
    def format_results(self, analysis_result: Dict) -> str:
        """格式化分析结果"""
        output = []
        
        output.append(f"网站分析结果: {analysis_result['url']}")
        output.append("=" * 60)
        output.append("")
        
        output.append(f"是否使用Webpack: {'是' if analysis_result['is_webpack'] else '否'}")
        output.append(f"JavaScript文件数量: {len(analysis_result['js_files'])}")
        output.append(f"发现API接口: {analysis_result['total_apis']} 个")
        output.append(f"发现敏感信息: {analysis_result['total_sensitive']} 个")
        output.append("")
        
        # 详细分析结果
        for i, analysis in enumerate(analysis_result['analysis_results'], 1):
            output.append(f"文件 {i}: {analysis['url']}")
            output.append(f"  大小: {analysis['size']} 字节")
            output.append(f"  Webpack: {'是' if analysis['is_webpack'] else '否'}")
            output.append(f"  Source Map: {'是' if analysis['has_sourcemap'] else '否'}")
            
            if analysis['apis']:
                output.append("  API接口:")
                for api in analysis['apis'][:10]:  # 只显示前10个
                    output.append(f"    - {api}")
                if len(analysis['apis']) > 10:
                    output.append(f"    ... 还有 {len(analysis['apis'])-10} 个")
            
            if analysis['sensitive_info']:
                output.append("  敏感信息:")
                for info in analysis['sensitive_info']:
                    output.append(f"    - {info['category']}: {info['content'][:50]}...")
            
            output.append("")
        
        # 错误信息
        if analysis_result['errors']:
            output.append("错误信息:")
            for error in analysis_result['errors']:
                output.append(f"  - {error}")
            output.append("")
        
        return "\n".join(output) 