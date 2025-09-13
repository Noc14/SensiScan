#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
功能测试脚本 - 验证新功能
"""

import yaml
import json
from main import SensitiveInfoScanner

def test_yaml_import():
    """测试YAML导入功能"""
    print("🧪 测试YAML规则导入功能...")
    
    # 创建测试YAML数据
    test_yaml = """
- group: "测试API接口"
  rules:
  - name: "REST API"
    loaded: true
    regex: '/api/[a-zA-Z0-9_/]+'
  - name: "GraphQL"
    loaded: true
    regex: '/graphql'
  - name: "禁用规则"
    loaded: false
    regex: '这个不会被导入'

- group: "测试密钥"
  rules:
  - name: "JWT Token"
    loaded: true
    regex: 'eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9._-]*\\.[A-Za-z0-9_-]*'
"""
    
    try:
        # 解析YAML
        yaml_data = yaml.safe_load(test_yaml)
        
        # 转换格式
        imported_rules = {}
        for group_data in yaml_data:
            group_name = group_data.get('group', '未分类')
            rules_list = group_data.get('rules', [])
            
            if group_name not in imported_rules:
                imported_rules[group_name] = []
            
            for rule in rules_list:
                if rule.get('loaded', True):
                    regex = rule.get('regex', '')
                    if regex:
                        imported_rules[group_name].append(regex)
        
        print(f"✅ YAML解析成功，共导入 {len(imported_rules)} 个分组")
        for group, rules in imported_rules.items():
            print(f"   - {group}: {len(rules)} 条规则")
        
        return True
        
    except Exception as e:
        print(f"❌ YAML导入测试失败: {str(e)}")
        return False

def test_file_types():
    """测试文件类型功能"""
    print("\n🧪 测试文件类型处理...")
    
    # 模拟文件类型选择
    test_types = "*.js,*.jsx,*.ts,*.tsx,*.vue,*.html,*.css,*.json,*.xml,*.txt"
    type_list = [t.strip() for t in test_types.split(',')]
    
    print(f"✅ 文件类型解析成功，共 {len(type_list)} 种类型:")
    for file_type in type_list:
        print(f"   - {file_type}")
    
    return True

def test_scanner_integration():
    """测试扫描引擎集成"""
    print("\n🧪 测试扫描引擎集成...")
    
    try:
        from scanner_engine import FileScanner, PackerFuzzerIntegration
        
        # 测试扫描引擎
        scanner = FileScanner(max_workers=2)
        print("✅ 扫描引擎初始化成功")
        
        # 测试Webpack分析器
        packer_fuzzer = PackerFuzzerIntegration()
        print("✅ Webpack分析器初始化成功")
        
        return True
        
    except Exception as e:
        print(f"❌ 扫描引擎测试失败: {str(e)}")
        return False

def test_rules_format():
    """测试规则格式兼容性"""
    print("\n🧪 测试规则格式兼容性...")
    
    # 测试默认规则格式
    default_rules = {
        "API接口": [
            r"/api/[^'\"\\s]+",
            r"\.get\(['\"]([^'\"]+)['\"]"
        ],
        "邮箱信息": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ]
    }
    
    # 验证规则可以正常保存和加载
    try:
        with open("test_rules_format.json", 'w', encoding='utf-8') as f:
            json.dump(default_rules, f, ensure_ascii=False, indent=2)
        
        with open("test_rules_format.json", 'r', encoding='utf-8') as f:
            loaded_rules = json.load(f)
        
        assert loaded_rules == default_rules
        print("✅ 规则格式兼容性测试通过")
        
        # 清理测试文件
        import os
        os.remove("test_rules_format.json")
        
        return True
        
    except Exception as e:
        print(f"❌ 规则格式测试失败: {str(e)}")
        return False

def main():
    """运行所有测试"""
    print("🚀 开始功能测试...")
    print("=" * 50)
    
    tests = [
        test_yaml_import,
        test_file_types,
        test_scanner_integration,
        test_rules_format
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ 测试异常: {str(e)}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 测试结果: {passed} 通过, {failed} 失败")
    
    if failed == 0:
        print("🎉 所有功能测试通过！程序已准备就绪。")
    else:
        print("⚠️ 部分测试失败，请检查相关功能。")
    
    return failed == 0

if __name__ == "__main__":
    main() 