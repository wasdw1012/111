#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析991个快速响应的共同特征
寻找可利用的密码学模式
"""

import json
import hashlib
from collections import Counter

# 加载筛选后的数据
print("[*] 加载快速响应数据...")
with open('fast_signatures_only.json', 'r') as f:
    fast_data = json.load(f)

signatures = fast_data['signatures']
print(f"[+] 加载了 {len(signatures)} 个快速响应签名")

# 分析证书哈希分布
print("\n[证书哈希分析]")
cert_hashes = [sig['cert_hash'] for sig in signatures]
unique_hashes = set(cert_hashes)
print(f"  唯一证书哈希: {len(unique_hashes)}个")

if len(unique_hashes) == 1:
    print(f"  所有请求返回相同证书: {list(unique_hashes)[0]}")
    print(f"  ✓ 这说明是同一个TLS端点")

# 分析时间戳间隔
print("\n[时间戳分析]")
timestamps = [sig['timestamp'] for sig in signatures]
intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
avg_interval = sum(intervals) / len(intervals)
print(f"  平均请求间隔: {avg_interval:.3f}秒")
print(f"  总采集时间: {timestamps[-1] - timestamps[0]:.1f}秒")

# 分析响应时间的精细分布
print("\n[响应时间精细分布]")
times = [sig['response_time'] for sig in signatures]
time_ranges = {
    '285-290ms': sum(1 for t in times if 285 <= t < 290),
    '290-295ms': sum(1 for t in times if 290 <= t < 295),
    '295-300ms': sum(1 for t in times if 295 <= t < 300),
    '300-302.38ms': sum(1 for t in times if 300 <= t < 302.38)
}

for range_name, count in time_ranges.items():
    percentage = 100 * count / len(times)
    print(f"  {range_name}: {count}个 ({percentage:.1f}%)")

# 寻找模式
print("\n[模式识别]")

# 检查是否有周期性
def check_periodicity(times, period):
    """检查是否有周期性模式"""
    pattern_match = 0
    for i in range(len(times) - period):
        if abs(times[i] - times[i + period]) < 5:  # 5ms容差
            pattern_match += 1
    return pattern_match / (len(times) - period)

periods_to_check = [10, 20, 50, 100]
for period in periods_to_check:
    match_rate = check_periodicity(times, period)
    if match_rate > 0.3:  # 30%以上匹配
        print(f"  [!] 发现周期{period}的模式: {match_rate:.1%}匹配")

# 检查连续快速响应
print("\n[连续性分析]")
max_consecutive = 0
current_consecutive = 0
prev_time = 0

for i, sig in enumerate(signatures):
    if i == 0:
        prev_time = sig['timestamp']
        current_consecutive = 1
        continue
    
    # 如果时间戳连续（间隔小于1秒）
    if sig['timestamp'] - prev_time < 1.0:
        current_consecutive += 1
        max_consecutive = max(max_consecutive, current_consecutive)
    else:
        current_consecutive = 1
    
    prev_time = sig['timestamp']

print(f"  最大连续快速响应: {max_consecutive}个")
print(f"  平均连续长度: {len(signatures) / (len(signatures) - max_consecutive):.1f}")

# 二进制特性分析
print("\n[二元特性验证]")
print(f"  快速组数量: {len(signatures)}")
print(f"  如果是MSB=0: 期望约50%, 实际{100*len(signatures)/1997:.1f}%")
print(f"  偏差: {abs(50 - 100*len(signatures)/1997):.1f}%")

if abs(50 - 100*len(signatures)/1997) < 5:
    print(f"  ✓ 非常接近50%，强烈暗示二元特性！")
    print(f"  ✓ 可能是: if (condition) {{ fast }} else {{ slow }}")

# 生成攻击假设
print("\n" + "="*60)
print("攻击假设")
print("="*60)

hypotheses = []

# 假设1: MSB相关
if 45 < 100*len(signatures)/1997 < 55:
    hypotheses.append({
        'name': 'MSB泄露',
        'confidence': 'HIGH',
        'description': '50/50分布暗示最高有效位泄露',
        'attack': '收集更多样本，使用格攻击恢复私钥'
    })

# 假设2: 缓存时序
if 15 < (max(times) - min(times)) < 25:
    hypotheses.append({
        'name': '缓存时序攻击',
        'confidence': 'MEDIUM',
        'description': '~20ms差异可能是缓存命中/未命中',
        'attack': 'Flush+Reload或Prime+Probe攻击'
    })

# 假设3: Montgomery ladder
if len(unique_hashes) == 1:
    hypotheses.append({
        'name': 'Montgomery Ladder分支',
        'confidence': 'MEDIUM',
        'description': '固定证书+二元分布=可能的ladder泄露',
        'attack': '分析ECDSA标量乘法实现'
    })

for i, hyp in enumerate(hypotheses, 1):
    print(f"\n假设{i}: {hyp['name']}")
    print(f"  置信度: {hyp['confidence']}")
    print(f"  描述: {hyp['description']}")
    print(f"  攻击方法: {hyp['attack']}")

# 生成下一步行动计划
print("\n" + "="*60)
print("行动计划")
print("="*60)

print("""
1. [立即] 验证二元假设
   - 再收集1000个样本，看是否保持50/50
   - 如果是，几乎确定是二元条件

2. [高优先级] 测试MSB假设
   - 使用这991个快速响应
   - 假设它们的nonce MSB=0
   - 尝试格攻击

3. [中优先级] 深入分析
   - 检查服务器软件（nginx/apache?）
   - 查找已知的时序漏洞
   - 测试不同的SNI/cipher suite

4. [如果上述失败] 统计攻击
   - 19.73ms足够大，可以远程利用
   - 收集10000+样本进行统计分析
""")

print("\n[!] 这是一个高质量的侧信道泄露！")
print("[!] 991个样本足够尝试初步攻击")
print("[!] 建议立即开始格攻击测试")