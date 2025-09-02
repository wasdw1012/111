#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
演示：100个签名的MSB都是0000，为什么仍然有用
"""

import random
import hashlib

# 模拟P-256曲线参数
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def simulate_ecdsa_signatures_with_msb_bias(count=100):
    """
    模拟100个ECDSA签名，每个nonce的MSB都是0000
    但是每个nonce都不同！
    """
    signatures = []
    
    print(f"[*] 生成{count}个签名，每个nonce的前4位都是0...")
    print("="*60)
    
    for i in range(count):
        # 生成一个252位的随机数（因为前4位固定为0）
        random_252_bits = random.getrandbits(252)
        
        # 这就是我们的nonce k，前4位是0，后252位随机
        k = random_252_bits  # 自动就是 < 2^252
        
        # 模拟签名过程
        # r = (k * G).x mod n
        r = (k * 12345) % n  # 简化模拟
        
        # s = k^(-1) * (h + d*r) mod n
        h = random.getrandbits(256)  # 消息哈希
        d = 0x123456789ABCDEF  # 私钥（未知）
        s = ((h + d * r) * pow(k, -1, n)) % n
        
        # 检查k的二进制表示
        k_binary = bin(k)[2:].zfill(256)
        
        signatures.append({
            'index': i,
            'k': k,
            'k_first_4_bits': k_binary[:4],
            'k_bits': len(k_binary),
            'r': r,
            's': s,
            'h': h
        })
        
        # 每20个输出一次
        if (i + 1) % 20 == 0:
            print(f"[+] 签名 {i+1}:")
            print(f"    k = {hex(k)[:20]}... ({len(bin(k)[2:])} bits)")
            print(f"    前4位: {k_binary[:4]}")
            print(f"    r = {hex(r)[:20]}...")
            print()
    
    return signatures

def show_why_msb_bias_helps():
    """
    解释为什么100个"MSB都是0"的签名有用
    """
    print("\n" + "="*60)
    print("为什么100个MSB=0000的签名有用？")
    print("="*60)
    
    # 生成100个签名
    sigs = simulate_ecdsa_signatures_with_msb_bias(100)
    
    # 检查所有k的前4位
    all_msb = [sig['k_first_4_bits'] for sig in sigs]
    all_zeros = all(msb == '0000' for msb in all_msb)
    
    print(f"\n[验证] 所有{len(sigs)}个nonce的前4位都是0000? {all_zeros}")
    
    # 但是k值都不同！
    unique_k = len(set(sig['k'] for sig in sigs))
    print(f"[验证] 有多少个不同的k值? {unique_k}/{len(sigs)}")
    
    # 展示几个k值
    print("\n[示例] 前5个nonce（虽然都是0000开头，但完全不同）：")
    for i in range(5):
        k = sigs[i]['k']
        print(f"  k{i+1} = {hex(k)}")
    
    print("\n[关键点]")
    print("1. 虽然100个nonce都是0000开头")
    print("2. 但它们是100个【不同】的252位随机数")
    print("3. 每个提供一个方程: d*r ≡ s*k - h (mod n)")
    print("4. 100个方程 + k<2^252的约束 = 可以解出私钥d")
    
    # 模拟格攻击
    print("\n" + "="*60)
    print("格攻击原理")
    print("="*60)
    
    print("\n构造格矩阵（简化示例）：")
    print("每个签名贡献一行，利用k < 2^252的约束")
    print()
    print("[ n   0   0  ...  t1 ]")
    print("[ 0   n   0  ...  t2 ]")
    print("[ 0   0   n  ...  t3 ]")
    print("[...              ...]")
    print("[ 0   0   0  ... 2^252]")
    print()
    print("其中 ti = ri/si mod n")
    print()
    print("LLL约简后，最短向量包含私钥d！")
    
    # 展示搜索空间缩小
    print("\n[搜索空间缩小]")
    print(f"原始空间: 2^256 ≈ {2**256:.2e}")
    print(f"MSB=0000后: 2^252 ≈ {2**252:.2e}")
    print(f"缩小倍数: {2**4} = 16倍")
    print()
    print("看起来只缩小16倍，但配合100个方程，足够破解！")
    
    return sigs

def demonstrate_lattice_attack_concept():
    """
    演示格攻击的概念（不是真实攻击代码）
    """
    print("\n" + "="*60)
    print("格攻击伪代码")
    print("="*60)
    
    code = '''
def lattice_attack(signatures):
    """
    利用MSB偏差的格攻击
    """
    # 1. 构造格
    n = curve_order
    m = len(signatures)  # 100个签名
    
    # 格维度 = m + 1
    L = Matrix(m + 1, m + 1)
    
    for i in range(m):
        r, s, h = signatures[i]
        t = (r * inverse(s, n)) % n
        u = (-h * inverse(s, n)) % n
        
        # 对角线放n
        L[i][i] = n
        # 最后一列放t
        L[i][m] = t
    
    # 最后一行利用MSB=0的约束
    L[m][m] = 2^252  # 因为k < 2^252
    
    # 2. LLL约简
    L_reduced = L.LLL()
    
    # 3. 提取私钥
    for row in L_reduced:
        possible_d = row[m] % n
        if verify_private_key(possible_d, signatures):
            return possible_d  # 找到私钥！
    
    return None
'''
    print(code)
    
    print("\n[实际工具]")
    print("1. SageMath - 最好的格攻击环境")
    print("2. fpylll - Python的LLL库")
    print("3. https://github.com/mimoo/lattice-attacks - 现成的实现")

if __name__ == "__main__":
    # 演示
    print("="*60)
    print("ECDSA MSB偏差演示")
    print("解答你的疑惑：为什么100个MSB都是0仍然有用")
    print("="*60)
    
    # 展示原理
    sigs = show_why_msb_bias_helps()
    
    # 展示攻击概念
    demonstrate_lattice_attack_concept()
    
    print("\n[总结]")
    print("✓ 100个签名的MSB都是0000 ≠ 100个相同的nonce")
    print("✓ 而是100个不同的252位数，都满足 < 2^252")
    print("✓ 这个共同约束让格攻击可行")
    print("✓ 不是直接猜nonce，而是解方程组")
    print("\n明白了吗？ 😊")