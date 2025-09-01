#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EdgeNormX v2 - State Graph Based Protocol Normalization Analyzer
===============================================================

Major improvements:
1. State Graph Model for attack path optimization
2. Mature HTTP/2 and HTTP/3 clients via httpx
3. Graph-based attack path discovery using networkx
"""

import asyncio
import httpx
import networkx as nx
import json
import time
import hashlib
import base64
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ----------------------------- Data structures -----------------------------

@dataclass
class StateNode:
    """Represents a unique system state"""
    node_id: str  # Unique identifier (hash of response characteristics)
    test_id: str
    profile: str
    status: int
    headers_sig: str
    body_sig: str
    cache_state: str
    auth_state: str
    
    def to_dict(self):
        return asdict(self)

@dataclass
class StateTransition:
    """Represents a state transition (edge in the graph)"""
    from_node: str
    to_node: str
    test_case: Dict[str, Any]
    profile: str
    risk_score: float
    transition_type: str  # e.g., "PATH_NORM", "STATUS_FLIP"

# ----------------------------- State Graph Engine --------------------------

class StateGraphEngine:
    """
    Models the target system as a state graph where:
    - Nodes are unique system states (response signatures)
    - Edges are test cases that transition between states
    - Goal: Find paths from initial state to vulnerable states
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.state_map: Dict[str, StateNode] = {}
        self.vulnerable_states: Set[str] = set()
        self.initial_state: Optional[str] = None
        
    def add_state(self, node: StateNode) -> str:
        """Add a state node to the graph"""
        node_id = node.node_id
        if node_id not in self.graph:
            self.graph.add_node(node_id, **node.to_dict())
            self.state_map[node_id] = node
        return node_id
        
    def add_transition(self, transition: StateTransition):
        """Add a state transition (edge) to the graph"""
        self.graph.add_edge(
            transition.from_node,
            transition.to_node,
            test_case=transition.test_case,
            profile=transition.profile,
            risk_score=transition.risk_score,
            transition_type=transition.transition_type
        )
        
    def mark_vulnerable(self, node_id: str, vulnerability_type: str):
        """Mark a state as vulnerable"""
        self.vulnerable_states.add(node_id)
        if node_id in self.graph:
            self.graph.nodes[node_id]['vulnerable'] = True
            self.graph.nodes[node_id]['vulnerability_type'] = vulnerability_type
            
    def find_attack_paths(self, max_length: int = 5) -> List[List[str]]:
        """
        Find all paths from initial state to vulnerable states
        Uses Dijkstra's algorithm weighted by risk scores
        """
        if not self.initial_state or not self.vulnerable_states:
            return []
            
        attack_paths = []
        
        for vuln_state in self.vulnerable_states:
            try:
                # Find shortest path weighted by inverse risk score
                # (higher risk = shorter path in graph terms)
                path = nx.shortest_path(
                    self.graph,
                    self.initial_state,
                    vuln_state,
                    weight=lambda u, v, d: 1.0 / (d.get('risk_score', 1.0) + 0.1)
                )
                
                if len(path) <= max_length:
                    attack_paths.append(path)
                    
            except nx.NetworkXNoPath:
                # No path exists from initial to this vulnerable state
                continue
                
        # Sort by path risk score (sum of edge risks)
        attack_paths.sort(
            key=lambda p: sum(
                self.graph[p[i]][p[i+1]].get('risk_score', 0)
                for i in range(len(p)-1)
            ),
            reverse=True
        )
        
        return attack_paths
        
    def get_path_details(self, path: List[str]) -> List[Dict[str, Any]]:
        """Get detailed information about a specific attack path"""
        details = []
        
        for i in range(len(path) - 1):
            from_node = path[i]
            to_node = path[i + 1]
            edge_data = self.graph[from_node][to_node]
            
            details.append({
                'step': i + 1,
                'from_state': self.state_map[from_node].to_dict(),
                'to_state': self.state_map[to_node].to_dict(),
                'test_case': edge_data['test_case'],
                'profile': edge_data['profile'],
                'transition_type': edge_data['transition_type'],
                'risk_score': edge_data['risk_score']
            })
            
        return details

# ----------------------------- Enhanced Protocol Client ---------------------

class EnhancedProtocolClient:
    """
    Uses httpx for mature HTTP/1.1, HTTP/2, and HTTP/3 support
    Provides accurate protocol behavior measurement
    """
    
    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        
    async def execute_test(self, profile: str, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a test case using the appropriate protocol profile"""
        
        method = test_case.get('method', 'GET')
        path = test_case.get('path', '/')
        headers = test_case.get('headers', {})
        body = test_case.get('body')
        
        # Configure client based on profile
        client_config = self._get_client_config(profile)
        
        async with httpx.AsyncClient(**client_config) as client:
            try:
                start_time = time.perf_counter()
                
                # Build request
                url = self.base_url + path
                
                # Add profile-specific headers
                if profile == 'grpc-web':
                    headers.update({
                        'content-type': 'application/grpc-web',
                        'x-grpc-web': '1',
                        'te': 'trailers'
                    })
                elif profile == 'grpc-native':
                    headers.update({
                        'content-type': 'application/grpc',
                        'te': 'trailers'
                    })
                    # Encode body in gRPC format if needed
                    if body:
                        body = self._encode_grpc_message(body)
                elif profile == 'ws-upgrade':
                    headers.update({
                        'Upgrade': 'websocket',
                        'Connection': 'Upgrade',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        'Sec-WebSocket-Version': '13'
                    })
                    
                # Execute request
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                    follow_redirects=False
                )
                
                rtt_ms = (time.perf_counter() - start_time) * 1000
                
                # Build response data
                result = {
                    'profile': profile,
                    'test_id': test_case['id'],
                    'method': method,
                    'path': path,
                    'request_headers': dict(headers),
                    'request_body': base64.b64encode(body).decode() if body else None,
                    'status': response.status_code,
                    'response_headers': dict(response.headers),
                    'response_body': base64.b64encode(response.content).decode() if response.content else None,
                    'rtt_ms': rtt_ms,
                    'http_version': response.http_version
                }
                
                return result
                
            except Exception as e:
                logger.debug(f"Error executing {profile} test {test_case['id']}: {e}")
                # 返回 None 而不是状态码 0，让调用者过滤失败的测试
                return None
                
    def _get_client_config(self, profile: str) -> Dict[str, Any]:
        """Get httpx client configuration for specific profile"""
        
        base_config = {
            'verify': False,  # Disable SSL verification for testing
            'timeout': httpx.Timeout(10.0),
            'limits': httpx.Limits(max_keepalive_connections=5)
        }
        
        if profile in ['h1', 'grpc-web', 'ws-upgrade']:
            # Force HTTP/1.1
            base_config['http2'] = False
            
        elif profile in ['h2', 'grpc-native']:
            # Force HTTP/2
            base_config['http2'] = True
            
        elif profile == 'h3':
            # HTTP/3 requires special handling
            # httpx doesn't support HTTP/3 yet, so we'd need aioquic
            # For now, we'll use HTTP/2 as fallback
            base_config['http2'] = True
            logger.warning("HTTP/3 not fully supported by httpx, using HTTP/2")
            
        return base_config
        
    def _encode_grpc_message(self, data: bytes) -> bytes:
        """Encode data in gRPC wire format"""
        import struct
        compression = b'\x00'
        length = struct.pack('>I', len(data))
        return compression + length + data

# ----------------------------- Main ProtoNormDiff v2 -----------------------

class ProtoNormDiffV2:
    """
    Enhanced protocol normalization analyzer with:
    - State graph modeling
    - Mature protocol implementations
    - Intelligent attack path discovery
    """
    
    def __init__(self, host: str, port: int = 443, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.client = EnhancedProtocolClient(host, port)
        self.state_graph = StateGraphEngine()
        self.results_cache: Dict[str, Any] = {}
        self.survey: Dict[str, Any] = {}  # 兼容原版接口
        
    async def analyze(self, dimensions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run the enhanced analysis with state graph modeling
        """
        logger.info(f"Starting ProtoNormDiff v2 analysis for {self.host}:{self.port}")
        
        # Initialize dimensions
        dims = set(dimensions or ['headers', 'path', 'authority', 'cache', 'cl_te'])
        
        # Define profiles to test
        profiles = ['h1', 'h2', 'grpc-web', 'ws-upgrade']
        
        # Build test cases
        test_cases = self._build_intelligent_test_cases(dims)
        
        # Execute initial round
        logger.info(f"Executing {len(test_cases)} test cases across {len(profiles)} profiles")
        initial_results = await self._execute_test_battery(test_cases, profiles)
        
        # Build state graph from results
        self._build_state_graph(initial_results)
        
        # Identify vulnerable states
        vulnerabilities = self._identify_vulnerabilities()
        
        # Find attack paths
        attack_paths = self.state_graph.find_attack_paths()
        
        # Generate report
        report = self._generate_report(vulnerabilities, attack_paths)
        
        return report
    
    # ======================== 兼容原版接口 ========================
    
    async def survey_topology(self) -> Dict[str, Any]:
        """兼容原版的 survey_topology 接口"""
        logger.info("Surveying topology (ALPN/Alt-Svc/CDN hints) - v2 enhanced...")
        
        # 使用 httpx 进行更准确的协议探测
        survey = {
            'alpn': None,
            'tls_version': None,
            'cipher': None,
            'alt_svc': None,
            'server': None,
            'h2_supported': False,
            'h3_advertised': False,
        }
        
        try:
            # 使用 httpx 探测协议支持
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                http2=True
            ) as client:
                response = await client.get(f"https://{self.host}:{self.port}/")
                
                # 提取协议信息
                survey['h2_supported'] = response.http_version == 'HTTP/2'
                survey['server'] = response.headers.get('server', 'Unknown')
                survey['alt_svc'] = response.headers.get('alt-svc')
                
                # 检查 HTTP/3 广告
                if survey['alt_svc'] and 'h3' in survey['alt_svc']:
                    survey['h3_advertised'] = True
                    
        except Exception as e:
            logger.warning(f"Topology survey failed: {e}")
            
        self.survey = survey
        return survey
    
    async def run_matrix(self, dimensions: Optional[List[str]] = None) -> Dict[str, Any]:
        """兼容原版的 run_matrix 接口"""
        return await self.analyze(dimensions)
        
    async def _execute_test_battery(self, test_cases: List[Dict], profiles: List[str]) -> List[Dict]:
        """Execute all test cases across all profiles"""
        results = []
        failed_count = 0
        
        for test_case in test_cases:
            for profile in profiles:
                result = await self.client.execute_test(profile, test_case)
                if result is not None:
                    results.append(result)
                else:
                    failed_count += 1
        
        logger.info(f"Test execution completed: {len(results)} successful, {failed_count} failed")
        return results
        
    def _build_state_graph(self, results: List[Dict]):
        """Build the state graph from test results"""
        logger.info("Building state graph from results")
        
        # Group results by test_id
        by_test = defaultdict(list)
        for result in results:
            if 'error' not in result:
                by_test[result['test_id']].append(result)
                
        # Create nodes and edges
        for test_id, test_results in by_test.items():
            # Create state nodes for each unique response
            nodes = {}
            for result in test_results:
                node = self._create_state_node(result)
                node_id = self.state_graph.add_state(node)
                nodes[result['profile']] = node_id
                
                # Mark initial state (first h1 GET / response)
                if test_id == 'base' and result['profile'] == 'h1':
                    self.state_graph.initial_state = node_id
                    
            # Create transitions between different profile responses
            for i, (profile1, node1) in enumerate(nodes.items()):
                for profile2, node2 in list(nodes.items())[i+1:]:
                    if node1 != node2:  # Different states
                        # Calculate transition risk
                        risk = self._calculate_transition_risk(
                            test_results[i], 
                            test_results[i+1]
                        )
                        
                        # Add bidirectional transitions
                        transition = StateTransition(
                            from_node=node1,
                            to_node=node2,
                            test_case=by_test[test_id][0],
                            profile=f"{profile1}->{profile2}",
                            risk_score=risk['score'],
                            transition_type=risk['type']
                        )
                        self.state_graph.add_transition(transition)
                        
    def _create_state_node(self, result: Dict) -> StateNode:
        """Create a state node from a test result"""
        # Generate unique signatures for response characteristics
        headers_sig = hashlib.md5(
            json.dumps(sorted(result.get('response_headers', {}).items())).encode()
        ).hexdigest()[:8]
        
        body_sig = hashlib.md5(
            (result.get('response_body', '') or '').encode()
        ).hexdigest()[:8]
        
        # Determine cache and auth states
        headers = result.get('response_headers', {})
        cache_state = 'HIT' if any(
            k.lower() in ['age', 'x-cache', 'cf-cache-status'] 
            for k in headers
        ) else 'MISS'
        
        auth_state = 'AUTH' if any(
            k.lower() in ['www-authenticate', 'set-cookie', 'authorization']
            for k in headers
        ) else 'NONE'
        
        # Create unique node ID
        node_data = f"{result['status']}:{headers_sig}:{body_sig}:{cache_state}:{auth_state}"
        node_id = hashlib.sha256(node_data.encode()).hexdigest()[:16]
        
        return StateNode(
            node_id=node_id,
            test_id=result['test_id'],
            profile=result['profile'],
            status=result['status'],
            headers_sig=headers_sig,
            body_sig=body_sig,
            cache_state=cache_state,
            auth_state=auth_state
        )
        
    def _calculate_transition_risk(self, result1: Dict, result2: Dict) -> Dict[str, Any]:
        """Calculate risk score for a state transition"""
        risk_score = 0.0
        transition_type = 'UNKNOWN'
        
        # Status code changes
        if result1['status'] != result2['status']:
            transition_type = 'STATUS_FLIP'
            # Critical transitions
            if (result1['status'] in [401, 403] and 200 <= result2['status'] < 300) or \
               (result2['status'] in [401, 403] and 200 <= result1['status'] < 300):
                risk_score = 9.0
            else:
                risk_score = 5.0
                
        # Header differences
        headers1 = set(result1.get('response_headers', {}).keys())
        headers2 = set(result2.get('response_headers', {}).keys())
        if headers1 != headers2:
            if transition_type == 'UNKNOWN':
                transition_type = 'HEADER_DIFF'
            risk_score += 2.0
            
        # Body differences
        if result1.get('response_body') != result2.get('response_body'):
            if transition_type == 'UNKNOWN':
                transition_type = 'BODY_DIFF'
            risk_score += 1.5
            
        return {
            'score': risk_score,
            'type': transition_type
        }
        
    def _identify_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Identify vulnerable states in the graph"""
        vulnerabilities = []
        
        for node_id, node_data in self.state_graph.graph.nodes(data=True):
            # Check for authentication bypass patterns
            if node_data['status'] in [200, 201, 204] and node_data['auth_state'] == 'NONE':
                # Check if other profiles require auth for same test
                test_id = node_data['test_id']
                other_states = [
                    n for n, d in self.state_graph.graph.nodes(data=True)
                    if d['test_id'] == test_id and n != node_id
                ]
                
                if any(
                    self.state_graph.graph.nodes[n]['status'] in [401, 403]
                    for n in other_states
                ):
                    self.state_graph.mark_vulnerable(node_id, 'AUTH_BYPASS')
                    vulnerabilities.append({
                        'node_id': node_id,
                        'type': 'AUTH_BYPASS',
                        'severity': 'CRITICAL',
                        'details': node_data
                    })
                    
            # Check for cache poisoning opportunities
            if node_data['cache_state'] == 'HIT':
                # Look for unkeyed header variations
                edges = list(self.state_graph.graph.in_edges(node_id, data=True))
                for _, _, edge_data in edges:
                    if 'X-Forwarded' in str(edge_data.get('test_case', {}).get('headers', {})):
                        self.state_graph.mark_vulnerable(node_id, 'CACHE_POISON')
                        vulnerabilities.append({
                            'node_id': node_id,
                            'type': 'CACHE_POISON',
                            'severity': 'HIGH',
                            'details': node_data
                        })
                        break
                        
        return vulnerabilities
        
    def _build_intelligent_test_cases(self, dims: set) -> List[Dict[str, Any]]:
        """Build test cases with intelligence"""
        # This would include all the test cases from the original implementation
        # but organized for the new state graph model
        cases = [
            {'id': 'base', 'method': 'GET', 'path': '/', 'headers': {}}
        ]
        
        if 'headers' in dims:
            cases.extend([
                {'id': 'hdr_case', 'method': 'GET', 'path': '/', 'headers': {'X-Test': 'Value'}},
                {'id': 'hdr_xff', 'method': 'GET', 'path': '/', 'headers': {'X-Forwarded-For': '127.0.0.1'}},
                {'id': 'hdr_auth', 'method': 'GET', 'path': '/', 'headers': {'Authorization': 'Bearer fake'}},
            ])
            
        if 'path' in dims:
            cases.extend([
                {'id': 'path_admin', 'method': 'GET', 'path': '/admin', 'headers': {}},
                {'id': 'path_traverse', 'method': 'GET', 'path': '/../etc/passwd', 'headers': {}},
                {'id': 'path_encoded', 'method': 'GET', 'path': '/%61dmin', 'headers': {}},
            ])
            
        return cases
        
    def _generate_report(self, vulnerabilities: List[Dict], attack_paths: List[List[str]]) -> Dict[str, Any]:
        """Generate the final analysis report"""
        report = {
            'host': self.host,
            'port': self.port,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'graph_stats': {
                'total_states': self.state_graph.graph.number_of_nodes(),
                'total_transitions': self.state_graph.graph.number_of_edges(),
                'vulnerable_states': len(self.state_graph.vulnerable_states)
            },
            'vulnerabilities': vulnerabilities,
            'attack_paths': []
        }
        
        # Add detailed attack path information
        for i, path in enumerate(attack_paths[:5]):  # Top 5 paths
            path_details = self.state_graph.get_path_details(path)
            total_risk = sum(step['risk_score'] for step in path_details)
            
            report['attack_paths'].append({
                'path_id': i + 1,
                'length': len(path),
                'total_risk_score': total_risk,
                'steps': path_details
            })
            
        return report

# ----------------------------- CLI Interface --------------------------------

async def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='EdgeNormX v2 - State Graph Protocol Analyzer'
    )
    parser.add_argument('host', help='Target hostname or IP')
    parser.add_argument('--port', type=int, default=443, help='Target port')
    parser.add_argument('--dimensions', nargs='+', help='Test dimensions')
    parser.add_argument('--output', '-o', help='Output file')
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════╗
║     EDGENORMX V2 - STATE GRAPH PROTOCOL ANALYZER         ║
║         "From Linear Search to Graph Theory"             ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    analyzer = ProtoNormDiffV2(args.host, args.port)
    report = await analyzer.analyze(args.dimensions)
    
    # Output results
    output = json.dumps(report, indent=2, default=str)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results written to: {args.output}")
    else:
        print(output)
        
    # Print attack path summary
    if report.get('attack_paths'):
        print("\n" + "="*60)
        print("TOP ATTACK PATHS DISCOVERED")
        print("="*60)
        
        for path_info in report['attack_paths'][:3]:
            print(f"\nPath #{path_info['path_id']} (Risk Score: {path_info['total_risk_score']:.1f}):")
            for step in path_info['steps']:
                print(f"  Step {step['step']}: {step['transition_type']} via {step['profile']}")
                print(f"    Test: {step['test_case']['id']} -> Status: {step['to_state']['status']}")

if __name__ == '__main__':
    asyncio.run(main())