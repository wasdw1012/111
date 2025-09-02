#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
筛选快速响应签名用于ECDSA攻击
基于分析结果：阈值302.38ms，快速组平均296ms
"""

import json

# 加载你的2000个数据
with open('nonce_timing_2000.json', 'r') as f:
    data = json.load(f)

# 使用分析得出的最佳阈值
THRESHOLD = 302.38  # 最佳分割点

# 筛选快速响应
fast_signatures = []
slow_signatures = []

for sig in data['signatures'][:2000]:  # 只用前2000个
    if sig['response_time'] < THRESHOLD:
        fast_signatures.append(sig)
    else:
        slow_signatures.append(sig)

print(f"[分析结果]")
print(f"  阈值: {THRESHOLD:.2f}ms")
print(f"  快速组: {len(fast_signatures)}个")
print(f"  慢速组: {len(slow_signatures)}个")
print(f"  比例: {len(fast_signatures)}/{len(slow_signatures)} = {len(fast_signatures)/len(slow_signatures):.2f}")

# 计算平均值
fast_avg = sum(s['response_time'] for s in fast_signatures) / len(fast_signatures)
slow_avg = sum(s['response_time'] for s in slow_signatures) / len(slow_signatures)

print(f"\n[时序特征]")
print(f"  快速组平均: {fast_avg:.2f}ms")
print(f"  慢速组平均: {slow_avg:.2f}ms")
print(f"  时间差: {slow_avg - fast_avg:.2f}ms")

# 按时间段分析快速响应分布
periods = [
    ("初期(1-400)", fast_signatures[:200]),
    ("中期(401-1200)", fast_signatures[200:600] if len(fast_signatures) > 600 else fast_signatures[200:]),
    ("后期(1201-2000)", fast_signatures[600:] if len(fast_signatures) > 600 else [])
]

print(f"\n[快速响应时间分布]")
for name, period_sigs in periods:
    if period_sigs:
        print(f"  {name}: {len(period_sigs)}个")

# 保存快速响应用于攻击
output = {
    'target': data['target'],
    'analysis': {
        'threshold': THRESHOLD,
        'total_fast': len(fast_signatures),
        'total_slow': len(slow_signatures),
        'fast_avg_ms': fast_avg,
        'slow_avg_ms': slow_avg,
        'time_diff_ms': slow_avg - fast_avg,
        'attack_hypothesis': '快速响应可能对应特定的nonce模式或密码学特性'
    },
    'fast_signatures': fast_signatures,
    'slow_signatures': slow_signatures[:100]  # 保存100个慢速的做对比
}

# 保存完整数据
with open('filtered_signatures_full.json', 'w') as f:
    json.dump(output, f, indent=2)
    print(f"\n[+] 完整数据已保存到: filtered_signatures_full.json")

# 保存精简版（只有快速响应）
with open('fast_signatures_only.json', 'w') as f:
    json.dump({
        'target': data['target'],
        'threshold': THRESHOLD,
        'count': len(fast_signatures),
        'signatures': fast_signatures
    }, f, indent=2)
    print(f"[+] 快速响应已保存到: fast_signatures_only.json")

print(f"\n[下一步建议]")
print(f"  1. 分析这{len(fast_signatures)}个快速响应的共同特征")
print(f"  2. 17ms的稳定差异足够进行侧信道攻击")
print(f"  3. 快慢组50/50分布说明存在二元特性")
print(f"  4. 可能的攻击向量：")
print(f"     - 缓存时序攻击")
print(f"     - Montgomery ladder分支泄露")
print(f"     - nonce大小相关的时序差异")