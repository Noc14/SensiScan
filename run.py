#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
敏感信息扫描工具启动脚本
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

def check_dependencies():
    """检查依赖项"""
    missing_modules = []
    
    try:
        import tkinter
    except ImportError:
        missing_modules.append('tkinter')
    
    try:
        import pathlib
    except ImportError:
        missing_modules.append('pathlib')
    
    # 可选依赖
    optional_missing = []
    
    try:
        import requests
    except ImportError:
        optional_missing.append('requests')
    
    try:
        import bs4
    except ImportError:
        optional_missing.append('beautifulsoup4')
    
    try:
        import chardet
    except ImportError:
        optional_missing.append('chardet')
    
    if missing_modules:
        error_msg = f"缺少必需的模块: {', '.join(missing_modules)}\n"
        error_msg += "请运行: pip install -r requirements.txt"
        print(error_msg)
        return False
    
    if optional_missing:
        warning_msg = f"缺少可选模块: {', '.join(optional_missing)}\n"
        warning_msg += "某些功能可能无法正常工作。建议运行: pip install -r requirements.txt"
        print(f"警告: {warning_msg}")
    
    return True

def main():
    """主函数"""
    print("敏感信息扫描工具 v1.2")
    print("=" * 40)
    
    # 检查Python版本
    if sys.version_info < (3, 6):
        print("错误: 需要Python 3.6或更高版本")
        sys.exit(1)
    
    # 检查依赖项
    if not check_dependencies():
        sys.exit(1)
    
    try:
        # 导入主程序
        from main import SensitiveInfoScanner
        
        # 创建并运行应用
        app = SensitiveInfoScanner()
        
        print("程序启动成功!")
        print("使用说明:")
        print("1. 选择要扫描的文件夹")
        print("2. 配置扫描参数")
        print("3. 点击开始扫描")
        print("4. 查看扫描结果")
        print("\n更多功能请查看菜单栏的工具选项。")
        print("-" * 40)
        
        app.run()
        
    except ImportError as e:
        error_msg = f"导入模块失败: {str(e)}\n"
        error_msg += "请确保所有文件都在正确的位置。"
        print(f"错误: {error_msg}")
        sys.exit(1)
    
    except Exception as e:
        error_msg = f"程序启动失败: {str(e)}"
        print(f"错误: {error_msg}")
        sys.exit(1)

if __name__ == "__main__":
    main() 