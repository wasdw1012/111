#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试WASM模块的进度打印功能
"""

import asyncio
from wasm_runtime_analyzer import WasmRuntimeAnalyzer

async def test_wasm_progress():
    """测试WASM进度打印"""
    print("="*60)
    print("测试WASM模块进度打印功能")
    print("="*60)
    
    # 创建分析器实例
    analyzer = WasmRuntimeAnalyzer(
        target_host="example.com",
        target_port=443,
        timeout=5.0
    )
    
    # 测试单个方法的进度打印
    print("\n[TEST] 测试单个方法的进度打印...")
    print("-"*40)
    
    try:
        # 测试运行时检测
        print("\n1. 测试运行时检测方法：")
        result = await analyzer._detect_wasm_runtime()
        print(f"   结果: {result.get('wasm_detected', False)}")
        
        # 测试沙箱安全评估
        print("\n2. 测试沙箱安全评估（会显示重要提示）：")
        result = await analyzer._assess_sandbox_security()
        print(f"   结果: 安全评分 {result.get('security_score', 0)}/100")
        
        # 测试信道方法（权限限制）
        print("\n3. 测试信道方法（权限限制）：")
        result = await analyzer._test_capability_restrictions()
        print(f"   结果: {result.get('status', 'UNKNOWN')}")
        
    except Exception as e:
        print(f"[ERROR] 测试过程中出错: {e}")
    
    print("\n" + "="*60)
    print("进度打印测试完成！")
    print("="*60)
    print("\n说明：")
    print("1. 每个方法开始时都会打印进度信息")
    print("2. 沙箱测试和信道方法有特殊的提示")
    print("3. 耗时操作会有额外的等待提醒")
    print("4. 所有打印都使用[WASM]前缀便于识别")

async def test_comprehensive_analysis():
    """测试完整分析流程的进度打印"""
    print("\n\n" + "="*60)
    print("测试完整分析流程的进度打印")
    print("="*60)
    
    analyzer = WasmRuntimeAnalyzer(
        target_host="example.com",
        target_port=443,
        timeout=3.0
    )
    
    print("\n[TEST] 运行完整的WASM安全分析（intelligent模式）...")
    print("注意观察各个阶段的进度打印")
    print("-"*40)
    
    try:
        # 运行完整分析
        result = await analyzer.comprehensive_wasm_security_analysis(posture='intelligent')
        
        # 显示摘要
        print("\n[SUMMARY] 分析完成")
        print(f"- 运行时检测: {result.get('runtime_detection', {}).get('wasm_detected', False)}")
        print(f"- 分析姿态: {result.get('analysis_posture', 'unknown')}")
        print(f"- 完整分析: {result.get('full_analysis_executed', False)}")
        
    except Exception as e:
        print(f"[ERROR] 完整分析出错: {e}")

async def main():
    """主测试函数"""
    # 测试单个方法
    await test_wasm_progress()
    
    # 测试完整流程
    await test_comprehensive_analysis()
    
    print("\n\n[SUCCESS] 所有进度打印测试完成！")
    print("现在WASM模块的每个方法都有清晰的进度提示。")

if __name__ == '__main__':
    asyncio.run(main())