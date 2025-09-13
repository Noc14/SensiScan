#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试扫描引擎
"""

from scanner_engine import FileScanner

def test_scanner():
    print("测试扫描引擎...")
    
    # 创建扫描器
    scanner = FileScanner(max_workers=2)
    
    # 定义测试规则
    rules = {
        'API接口': [
            r'/api/[^\'\"\\s]+',
            r'\.get\([\'"]([^\'\"]+)[\'"]',
            r'\.post\([\'"]([^\'\"]+)[\'"]'
        ],
        '邮箱信息': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ],
        '密钥信息': [
            r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9_-]{16,})[\'"]',
            r'secret[_-]?key[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9_-]{16,})[\'"]'
        ]
    }
    
    # 结果收集
    results = []
    
    def progress_callback(msg):
        print(f"进度: {msg}")
    
    def result_callback(result):
        results.append(result)
        print(f"发现: {result['category']} - {result['content'][:50]}... (文件: {result['file']}, 行: {result['line']})")
    
    # 设置回调
    scanner.set_progress_callback(progress_callback)
    scanner.set_result_callback(result_callback)
    
    # 开始扫描
    scanner.scan_files('test_data', ['*.js', '*.py', '*.json'], rules)
    
    print(f"\n扫描完成！共发现 {len(results)} 个匹配项")
    
    # 按类别统计
    stats = {}
    for result in results:
        category = result['category']
        stats[category] = stats.get(category, 0) + 1
    
    print("\n统计结果:")
    for category, count in stats.items():
        print(f"  {category}: {count} 项")

if __name__ == "__main__":
    test_scanner() 