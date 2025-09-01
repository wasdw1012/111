import socket
import ssl
import struct
from typing import Dict, Tuple, Optional

class SmartServiceDetector:
    """智能服务检测器 - 在主探测前识别服务类型"""
    
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        
        # TLS ClientHello的前5字节特征
        self.TLS_SIGNATURE = b'\x16\x03'
        
        # 常见服务特征
        self.SERVICE_SIGNATURES = {
            b'SSH-': 'ssh',
            b'220 ': 'ftp',
            b'HTTP/': 'http',
            b'+OK': 'pop3',
            b'* OK': 'imap',
            b'220-': 'smtp',
        }
    
    def quick_detect(self, host: str, port: int) -> Dict[str, any]:
        """快速检测端口服务类型"""
        result = {
            'port': port,
            'service': 'unknown',
            'is_tls': False,
            'banner': None,
            'needs_https': False,
            'is_protected': False
        }
        
        # 1. 先尝试获取banner
        banner = self._grab_banner(host, port)
        if banner:
            result['banner'] = banner[:100]  # 只保留前100字节
            
            # 识别服务类型
            for signature, service in self.SERVICE_SIGNATURES.items():
                if banner.startswith(signature):
                    result['service'] = service
                    return result
        
        # 2. 检测是否是TLS/SSL端口
        is_tls = self._check_tls(host, port)
        result['is_tls'] = is_tls
        
        # 3. 根据端口号智能判断
        if port == 443 or (port == 8443):
            result['needs_https'] = True
            result['service'] = 'https'
        elif port == 80 or (port == 8080):
            # 80端口也可能是HTTPS（像你遇到的情况）
            if is_tls:
                result['needs_https'] = True
                result['service'] = 'https'
            else:
                result['service'] = 'http'
        elif port == 22000 or port == 2222:
            result['service'] = 'ssh'
            # 如果SSH端口没响应SSH banner，可能被保护
            if not banner or not banner.startswith(b'SSH-'):
                result['is_protected'] = True
        elif port == 3389:
            result['service'] = 'rdp'
            # RDP通常不会有banner响应
            if self._check_rdp(host, port):
                result['service'] = 'rdp'
            else:
                result['is_protected'] = True
        elif port == 8000:
            # 8000常用于HTTP管理接口
            result['service'] = 'http-alt'
            if is_tls:
                result['needs_https'] = True
        
        return result
    
    def _grab_banner(self, host: str, port: int) -> Optional[bytes]:
        """快速抓取banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # 发送最小探测包
            sock.send(b'\r\n')
            
            # 接收响应
            banner = sock.recv(1024)
            sock.close()
            return banner
        except:
            return None
    
    def _check_tls(self, host: str, port: int) -> bool:
        """检查是否支持TLS"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # 快速超时
            sock.connect((host, port))
            
            # 构造最简单的TLS ClientHello
            client_hello = b'\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03\x03'
            sock.send(client_hello)
            
            # 检查响应
            data = sock.recv(5)
            sock.close()
            
            # TLS响应以0x16开头
            return data and data[:2] == self.TLS_SIGNATURE
        except:
            return False
    
    def _check_rdp(self, host: str, port: int) -> bool:
        """检查是否是RDP服务"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((host, port))
            
            # RDP初始化连接请求 (简化版)
            rdp_request = b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00'
            sock.send(rdp_request)
            
            # 读取响应
            data = sock.recv(1024)
            sock.close()
            
            # RDP响应通常包含特定模式
            return data and (b'\x03\x00' in data[:4] or len(data) > 10)
        except:
            return False
    
    def detect_protection(self, host: str) -> Dict[str, bool]:
        """检测常见防护机制"""
        protection = {
            'has_waf': False,
            'has_rate_limit': False, 
            'blocks_scanning': False
        }
        
        # 简单WAF检测 - 发送恶意请求看响应
        try:
            sock = socket.socket()
            sock.settimeout(1.0)
            sock.connect((host, 80))
            
            # 发送可疑请求
            sock.send(b'GET /../../../etc/passwd HTTP/1.0\r\n\r\n')
            response = sock.recv(1024)
            
            # 检查WAF特征
            if b'403' in response or b'blocked' in response.lower():
                protection['has_waf'] = True
            
            sock.close()
        except:
            pass
        
        return protection

# 与主程序集成的辅助函数
def pre_detect_services(host: str, ports: list = None) -> Dict[int, Dict]:
    """预检测服务 - 在主探测前运行"""
    
    if ports is None:
        # 🚨 22000端口优先！同时扫描标准22端口防止SSL服务漏检
        ports = [22000, 22, 80, 443, 2222, 8080, 8443, 8000, 3389]
    
    detector = SmartServiceDetector(timeout=1.0)
    results = {}
    
    print(f"[*] Pre-detecting services on {host}...")
    
    for port in ports:
        result = detector.quick_detect(host, port)
        results[port] = result
        
        # 打印发现
        if result['service'] != 'unknown':
            print(f"  Port {port}: {result['service']}", end='')
            if result['is_tls']:
                print(" (TLS enabled)", end='')
            if result['is_protected']:
                print(" [PROTECTED]", end='')
            print()
    
    return results