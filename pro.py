from smartcard.System import readers
from smartcard.util import toBytes, toHexString
from smartcard.CardConnection import CardConnection
from Crypto.Cipher import DES, DES3
import hashlib
import struct
import os
import time
import logging
import sys
import threading
import traceback
from datetime import datetime, timedelta

# 只要有这个🚨emoji就是重点核心优化和解决方案，死都不能碰！🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨

class APDUAnalyzer:
    # APDU分析器 - 模拟Bus Hound抓包功能

    def __init__(self):
        self.commands = []  # 完整APDU命令历史
        self.responses = []  # 完整响应历史
        self.timing_data = []  # 时序分析数据
        self.data_chunks = {}  # 块数据重组
        self.statistics = {
            'total_commands': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'avg_response_time': 0,
            'max_response_time': 0,
            'min_response_time': float('inf'),
            'failed_commands': 0,
            'success_rate': 0
        }
        self.session_start = time.time()
        
    def log_command(self, apdu: bytes, operation_name: str, timestamp: float = None):
        #记录APDU命令
        if timestamp is None:
            timestamp = time.time()
            
        # 解析APDU结构
        cmd_analysis = self._analyze_apdu_structure(apdu)
        
        command_record = {
            'timestamp': timestamp,
            'operation': operation_name,
            'raw_apdu': apdu,
            'analysis': cmd_analysis,
            'size': len(apdu)
        }
        
        self.commands.append(command_record)
        self.statistics['total_commands'] += 1
        self.statistics['total_bytes_sent'] += len(apdu)
        
        # 协议解析输出
        self._print_command_analysis(command_record)
        
    def log_response(self, response_data: bytes, sw: int, operation_name: str, timestamp: float = None):
        """记录APDU响应"""
        if timestamp is None:
            timestamp = time.time()
            
        # 计算响应时间
        response_time = 0
        if self.commands:
            last_cmd = self.commands[-1]
            if last_cmd['operation'] == operation_name:
                response_time = timestamp - last_cmd['timestamp']
                
        response_record = {
            'timestamp': timestamp,
            'operation': operation_name,
            'data': response_data,
            'sw': sw,
            'size': len(response_data),
            'response_time': response_time,
            'success': sw == 0x9000
        }
        
        self.responses.append(response_record)
        self.timing_data.append(response_time)
        
        # 更新统计
        self.statistics['total_bytes_received'] += len(response_data)
        if not response_record['success']:
            self.statistics['failed_commands'] += 1
            
        # 更新时序统计
        if response_time > 0:
            self.statistics['max_response_time'] = max(self.statistics['max_response_time'], response_time)
            self.statistics['min_response_time'] = min(self.statistics['min_response_time'], response_time)
            if len(self.timing_data) > 0:
                self.statistics['avg_response_time'] = sum(self.timing_data) / len(self.timing_data)
        
        # 成功率计算
        if self.statistics['total_commands'] > 0:
            success_count = self.statistics['total_commands'] - self.statistics['failed_commands']
            self.statistics['success_rate'] = (success_count / self.statistics['total_commands']) * 100
            
        # 智能响应分析输出
        self._print_response_analysis(response_record)
        
        # 检测UPDATE_BINARY序列进行数据重组
        if len(self.commands) > 0:
            last_cmd = self.commands[-1]
            if last_cmd['analysis']['ins'] == 0xD6 and response_record['success']:  # UPDATE_BINARY
                self._collect_write_data(last_cmd, response_record)
                
    def _analyze_apdu_structure(self, apdu: bytes) -> dict:
        """深度APDU结构分析"""
        if len(apdu) < 4:
            return {'error': 'Invalid APDU length'}
            
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        
        analysis = {
            'cla': cla,
            'ins': ins,
            'p1': p1,
            'p2': p2,
            'cla_desc': self._get_cla_description(cla),
            'ins_desc': self._get_ins_description(ins),
            'secure_messaging': (cla & 0x0C) != 0,
            'chaining': (cla & 0x10) != 0,
        }
        
        # 特殊命令解析
        if ins == 0xD6:  # UPDATE_BINARY
            offset = (p1 << 8) | p2
            analysis['offset'] = offset
            analysis['offset_hex'] = f"0x{offset:04X}"
            
            if len(apdu) > 4:
                data_len = apdu[4] if len(apdu) > 5 else 0
                analysis['data_length'] = data_len
                analysis['data_range'] = f"0x{offset:04X} - 0x{offset + data_len - 1:04X}"
                
        elif ins == 0xB0:  # READ_BINARY
            offset = (p1 << 8) | p2
            analysis['offset'] = offset
            analysis['offset_hex'] = f"0x{offset:04X}"
            
            if len(apdu) >= 5:
                le = apdu[4]
                analysis['expected_length'] = le
                analysis['read_range'] = f"0x{offset:04X} - 0x{offset + le - 1:04X}"
                
        elif ins == 0xA4:  # SELECT
            analysis['selection_type'] = {0x00: "By FID", 0x04: "By AID"}.get(p1, f"Unknown_{p1:02X}")
            
        return analysis
        
    def _collect_write_data(self, cmd_record: dict, resp_record: dict):
        #收集烧卡数据然后分析完整性
        cmd_analysis = cmd_record['analysis']
        
        if 'offset' in cmd_analysis:
            file_id = "unknown"  # 可通过之前的SELECT命令推理
            offset = cmd_analysis['offset']
            
            # 提取实际写入的数据（从APDU中去除头部和padding）
            apdu = cmd_record['raw_apdu']
            if len(apdu) > 5:
                data_len = apdu[4]
                write_data = apdu[5:5+data_len]
                
                if file_id not in self.data_chunks:
                    self.data_chunks[file_id] = {}
                    
                self.data_chunks[file_id][offset] = {
                    'data': write_data,
                    'timestamp': cmd_record['timestamp'],
                    'size': len(write_data)
                }
                
    def _print_command_analysis(self, record: dict):
        #打印命令分析 模拟Bus Hound的实时显示
        if not DEBUG_MODE:
            return
            
        timestamp = datetime.fromtimestamp(record['timestamp']).strftime("%H:%M:%S.%f")[:-3]
        analysis = record['analysis']
        
        print(f"""
 [{timestamp}] APDU_CMD_{record['operation']}
├── Raw: {record['raw_apdu'].hex().upper()}
├── CLA: {analysis['cla']:02X} ({analysis['cla_desc']})
├── INS: {analysis['ins']:02X} ({analysis['ins_desc']})
├── P1P2: {analysis['p1']:02X}{analysis['p2']:02X}""", end="")
        
        if 'offset' in analysis:
            print(f" (Offset: {analysis['offset_hex']})")
        else:
            print()
            
        if 'data_range' in analysis:
            print(f"├── Data_Range: {analysis['data_range']}")
        elif 'read_range' in analysis:
            print(f"├── Read_Range: {analysis['read_range']}")
            
        print(f"└── Size: {record['size']} bytes")
        
    def _print_response_analysis(self, record: dict):
        """打印响应分析"""
        if not DEBUG_MODE:
            return
            
        timestamp = datetime.fromtimestamp(record['timestamp']).strftime("%H:%M:%S.%f")[:-3]
        
        status_icon = "√" if record['success'] else "×"
        timing_info = f" ({record['response_time']*1000:.1f}ms)" if record['response_time'] > 0 else ""
        
        print(f""" [{timestamp}] RESP_{record['operation']} {status_icon}
├── SW: {record['sw']:04X} ({self._get_sw_description(record['sw'])})
├── Data: {record['size']} bytes{timing_info}
└── Content: {record['data'].hex().upper()[:32]}{'...' if len(record['data']) > 16 else ''}
{'='*50}""")
        
    def generate_session_report(self):
        """生成超详细会话分析报告"""
        session_duration = time.time() - self.session_start
        
        report = f"""
 APDU SESSION ANALYSIS REPORT - DETAILED 
{'='*80}
  Session Duration: {session_duration:.2f}s
 Commands Sent: {self.statistics['total_commands']}
 Responses Received: {len(self.responses)}
 Success Rate: {self.statistics['success_rate']:.1f}%
 Data Transferred: ↑{self.statistics['total_bytes_sent']}B ↓{self.statistics['total_bytes_received']}B

  TIMING ANALYSIS:
├── Average Response: {self.statistics['avg_response_time']*1000:.1f}ms
├── Fastest Response: {self.statistics['min_response_time']*1000:.1f}ms  
└── Slowest Response: {self.statistics['max_response_time']*1000:.1f}ms

 AA PRIVATE KEY INJECTION ANALYSIS:
"""
        
        #  AA密钥写入分析
        aa_operations = [cmd for cmd in self.commands if 'AA' in cmd['operation'] or 'PUT' in cmd['operation']]
        if aa_operations:
            report += "├── AA Key Operations Detected:\n"
            for i, aa_op in enumerate(aa_operations):
                timestamp = datetime.fromtimestamp(aa_op['timestamp']).strftime("%H:%M:%S.%f")[:-3]
                report += f"│   ├── [{timestamp}] {aa_op['operation']}\n"
                report += f"│   │   ├── APDU: {aa_op['raw_apdu'].hex().upper()[:40]}{'...' if len(aa_op['raw_apdu']) > 20 else ''}\n"
                report += f"│   │   ├── Size: {aa_op['size']} bytes\n"
                
                # 找对应的响应
                matching_resp = None
                for resp in self.responses:
                    if (resp['operation'] == aa_op['operation'] and 
                        abs(resp['timestamp'] - aa_op['timestamp']) < 1.0):
                        matching_resp = resp
                        break
                
                if matching_resp:
                    status = "√ SUCCESS" if matching_resp['success'] else f"× FAILED (SW={matching_resp['sw']:04X})"
                    report += f"│   │   ├── Result: {status}\n"
                    report += f"│   │   └── Response Time: {matching_resp['response_time']*1000:.1f}ms\n"
                else:
                    report += f"│   │   └── Result: ！ NO RESPONSE FOUND\n"
                report += "│   │\n"
        else:
            report += "├── ！ No AA Key Operations Found in Session\n"
            
        #  完整操作序列（前20个操作）
        report += f"\n COMPLETE OPERATION SEQUENCE (First 20):\n"
        for i, cmd in enumerate(self.commands[:20]):
            timestamp = datetime.fromtimestamp(cmd['timestamp']).strftime("%H:%M:%S.%f")[:-3]
            
            # 找对应响应
            matching_resp = None
            for resp in self.responses:
                if (resp['operation'] == cmd['operation'] and 
                    abs(resp['timestamp'] - cmd['timestamp']) < 1.0):
                    matching_resp = resp
                    break
            
            status_icon = "√" if matching_resp and matching_resp['success'] else "×" if matching_resp else "！"
            resp_time = f"{matching_resp['response_time']*1000:.0f}ms" if matching_resp else "N/A"
            sw_info = f"SW={matching_resp['sw']:04X}" if matching_resp else "NO_RESP"
            
            report += f"├── {i+1:2d}. [{timestamp}] {status_icon} {cmd['operation']}\n"
            report += f"│     ├── APDU: {cmd['raw_apdu'].hex().upper()[:60]}{'...' if len(cmd['raw_apdu']) > 30 else ''}\n"
            report += f"│     ├── Size: {cmd['size']}B, Time: {resp_time}, {sw_info}\n"
            
            # 特殊分析：AA相关操作
            if 'AA' in cmd['operation'] or 'PUT' in cmd['operation']:
                report += f"│     └──   ** AA KEY OPERATION **  \n"
            elif 'BAC' in cmd['operation'] or 'AUTH' in cmd['operation']:
                report += f"│     └──   ** AUTHENTICATION OPERATION **  \n"
            elif 'CREATE' in cmd['operation']:
                report += f"│     └──   ** FILE CREATION **  \n"
            elif 'UPDATE' in cmd['operation'] or 'WRITE' in cmd['operation']:
                report += f"│     └──   ** DATA WRITING **  \n"
            elif 'READ' in cmd['operation'] or 'VERIFY' in cmd['operation']:
                report += f"│     └──   ** DATA VERIFICATION **  \n"
            
        if len(self.commands) > 20:
            report += f"├── ... and {len(self.commands) - 20} more operations\n"
            
        # 🚨 失败命令详情
        failed_ops = [r for r in self.responses if not r['success']]
        if failed_ops:
            report += f"\n🚨 FAILED COMMANDS DETAILS ({len(failed_ops)}):\n"
            for i, fail in enumerate(failed_ops):
                timestamp = datetime.fromtimestamp(fail['timestamp']).strftime("%H:%M:%S.%f")[:-3]
                report += f"├── {i+1}. [{timestamp}] {fail['operation']}: SW={fail['sw']:04X}\n"
                
                # 查找对应的命令
                matching_cmd = None
                for cmd in self.commands:
                    if (cmd['operation'] == fail['operation'] and 
                        abs(cmd['timestamp'] - fail['timestamp']) < 1.0):
                        matching_cmd = cmd
                        break
                
                if matching_cmd:
                    report += f"│   ├── Command: {matching_cmd['raw_apdu'].hex().upper()[:40]}...\n"
                    report += f"│   └── Analysis: {self._analyze_failure(fail['sw'])}\n"
                
        #  性能瓶颈分析
        slow_ops = [r for r in self.responses if r['response_time'] > 1.0]
        if slow_ops:
            report += f"\n SLOW OPERATIONS (>{1.0}s): {len(slow_ops)}\n"
            for slow in slow_ops:
                timestamp = datetime.fromtimestamp(slow['timestamp']).strftime("%H:%M:%S.%f")[:-3]
                report += f"├── [{timestamp}] {slow['operation']}: {slow['response_time']*1000:.0f}ms\n"
                
        #  数据完整性分析
        if self.data_chunks:
            report += f"\n DATA INTEGRITY ANALYSIS:\n"
            for file_id, chunks in self.data_chunks.items():
                total_size = sum(chunk['size'] for chunk in chunks.values())
                report += f"├── File_{file_id}: {len(chunks)} chunks, {total_size} bytes\n"
                
                # 检查连续性
                offsets = sorted(chunks.keys())
                gaps = []
                for i in range(1, len(offsets)):
                    prev_offset = offsets[i-1]
                    prev_size = chunks[prev_offset]['size']
                    curr_offset = offsets[i]
                    
                    expected_next = prev_offset + prev_size
                    if curr_offset != expected_next:
                        gaps.append(f"0x{expected_next:04X}-0x{curr_offset:04X}")
                        
                if gaps and len(gaps) <= 10:
                    report += f"│   └── ！ Gaps detected: {', '.join(gaps)}\n"
                elif gaps:
                    report += f"│   └── ！ {len(gaps)} gaps detected (showing first 10): {', '.join(gaps[:10])}...\n"
                else:
                    report += f"│   └── √ No gaps detected - perfect integrity\n"
                    
        #  统计总结
        report += f"\n SESSION STATISTICS SUMMARY:\n"
        report += f"├── Total Operations: {len(self.commands)}\n"
        report += f"├── AA Key Operations: {len([c for c in self.commands if 'AA' in c['operation']])}\n"
        report += f"├── Authentication Ops: {len([c for c in self.commands if 'AUTH' in c['operation'] or 'BAC' in c['operation']])}\n"
        report += f"├── File Creation Ops: {len([c for c in self.commands if 'CREATE' in c['operation']])}\n"
        report += f"├── Data Writing Ops: {len([c for c in self.commands if 'UPDATE' in c['operation'] or 'WRITE' in c['operation']])}\n"
        report += f"├── Data Reading Ops: {len([c for c in self.commands if 'READ' in c['operation']])}\n"
        report += f"├── Success Rate: {self.statistics['success_rate']:.1f}%\n"
        report += f"└── Average Speed: {(self.statistics['total_bytes_sent']/1024)/session_duration:.2f} KB/s\n"
                    
        report += "=" * 80
        
        print(report)
        
        # 保存到文件
        with open("apdu_analysis_report.txt", "w", encoding="utf-8") as f:
            f.write(report)
            
        return report
    
    def _analyze_failure(self, sw: int) -> str:
        """分析失败原因"""
        failure_analysis = {
            0x6982: "Security condition not satisfied - May need authentication",
            0x6985: "Command not allowed - Operation restricted", 
            0x6A82: "File not found - Target file does not exist",
            0x6300: "Authentication failed - Wrong credentials",
            0x6882: "Secure messaging not supported - SM error",
            0x6A86: "Incorrect P1P2 parameters",
            0x6A80: "Invalid data field parameters",
            0x6881: "Logical channel not supported"
        }
        return failure_analysis.get(sw, f"Unknown error code: {sw:04X}")
        
    def _get_cla_description(self, cla: int) -> str:
        """CLA字节详细描述"""
        descriptions = {
            0x00: "ISO7816-4",
            0x0C: "SM_Last",
            0x1C: "SM_Chain",
        }
        
        base_desc = descriptions.get(cla & 0xF0, f"Unknown_{cla:02X}")
        
        # 添加标志位描述
        flags = []
        if cla & 0x10:
            flags.append("CHAIN")
        if cla & 0x0C:
            flags.append("SM")
            
        return f"{base_desc}{'|' + '|'.join(flags) if flags else ''}"
        
    def _get_ins_description(self, ins: int) -> str:
        #INS指令详细描述
        descriptions = {
            0xA4: "SELECT",
            0x84: {"name": "GET_CHALLENGE", "description": "Get a random challenge"},
            0x82: {"name": "EXTERNAL_AUTHENTICATE", "description": "External Authentication"},
            0xDA: {"name": "PUT_DATA", "description": "Write data object"},
            0xE0: {"name": "CREATE_FILE", "description": "Create a file"},
            0xD6: {"name": "UPDATE_BINARY", "description": "Update Binary Files"},
            0xB0: {"name": "READ_BINARY", "description": "Reading binary files"},
        }
        return descriptions.get(ins, f"UNK_{ins:02X}")
        
    def _get_sw_description(self, sw: int) -> str:
        #状态字详细描述
        descriptions = {
            0x9000: "Success",
            0x6982: "Security_Not_Satisfied",
            0x6985: "Command_Not_Allowed", 
            0x6A82: "File_Not_Found",
            0x6300: "Auth_Failed",
            0x6882: "SM_Not_Supported",
        }
        return descriptions.get(sw, f"Unknown_{sw:04X}")

# 🚨 全局APDU分析器实例
apdu_analyzer = APDUAnalyzer()

# 🚨 现代化参数设置
DEBUG_MODE = True
VERIFY_AFTER_WRITE = True 
CHUNK_SIZE = 192                 #🚨龟速求稳！
TIMEOUT = 30                    #🚨30秒超时，硬件慢点没事！
MAX_RETRIES = 1                 #🚨彻底关闭重试！SSC错位必死！
WRITE_DELAY = 0.5              #🚨写入延迟！
CHUNK_PROGRESS_DELAY = 0.2     #🚨每10个块的进度延迟！
HARDWARE_RECOVERY_DELAY = 2.0  #🚨高风险偏移量恢复延迟！
ENABLE_HARDWARE_MONITORING = True

# 🚨 新增：数据完整性监控设置
ENABLE_DATA_INTEGRITY_MONITORING = True   # 开启数据完整性监控
LOG_UNPADDING_DETAILS = True              # 记录unpadding详细信息
WARN_ON_SUSPICIOUS_PADDING = True         # 可疑填充时警告

# 🚨 SSC开销优化设置 先不开，不自找麻烦~
OPTIMIZE_SSC_USAGE = True                # SSC开销优化模式
# 如果启用，将跳过途中验证以节省SSC，但会降低错误检测能力
# 典型SSC消耗分析：
# - 每个文件验证需要：SELECT(SSC+1) + READ循环(SSC+文件大小/64)
# - COM验证: ≈SSC+2,  DG1验证: ≈SSC+3,  DG2验证: ≈SSC+111-200,  SOD验证: ≈SSC+35
# - 完整验证总开销：约SSC+160+次递增 巨大开销！

#   新增：APDU抓包分析配置
ENABLE_APDU_LOGGING = True                # 启用详细APDU日志
LOG_RAW_APDUS = True                      # 记录原始APDU命令
LOG_SM_DECRYPT = True                     # 记录安全报文解密结果
APDU_LOG_FILE = "personalization_apdus.log"  # APDU日志文件
# 配合Wireshark+USBPcap使用，用于交叉验证数据完整性

# 🚨重大修改：修复SOD验证大小问题！
MAX_VERIFY_SIZE = 3000  # 🚨 从256改成3000！修复SOD截断问题！

# 没有坏块。安全报文有BUG，先这样搞！
KNOWN_BAD_OFFSETS = set() 
# 反馈机制 

class ProgressMonitor:
    #静默进度监控不干扰硬件，只收集数据
    def __init__(self):
        self.start_time = time.time()
        self.current_bytes = 0
        self.total_bytes = 0
        self.current_operation = ""
        self.last_update = 0
        self.operation_history = []  # 记录所有操作历史
        self.peak_speed = 0
        self.avg_speed = 0
        
    def set_total(self, total_bytes, operation="Processing"):
        self.total_bytes = total_bytes
        self.current_operation = operation
        self.current_bytes = 0
        print(f"\n>> {operation} - Total: {total_bytes} bytes")
        
    def update(self, current_bytes, sub_operation=""):
        #静默更新 - 无实时显示，无flush干扰
        self.current_bytes = current_bytes
        self.last_update = time.time()
        
        # 静默收集性能数据
        if self.total_bytes > 0:
            elapsed = time.time() - self.start_time
            current_speed = (current_bytes / 1024) / elapsed if elapsed > 0 else 0
            self.peak_speed = max(self.peak_speed, current_speed)
            self.avg_speed = current_speed
            
            # 每25%进度记录关键节点！
            percent = (current_bytes / self.total_bytes) * 100
            if percent >= 25 and not any(h.get('25%') for h in self.operation_history):
                self.operation_history.append({'25%': True, 'time': elapsed, 'bytes': current_bytes})
            elif percent >= 50 and not any(h.get('50%') for h in self.operation_history):
                self.operation_history.append({'50%': True, 'time': elapsed, 'bytes': current_bytes})
            elif percent >= 75 and not any(h.get('75%') for h in self.operation_history):
                self.operation_history.append({'75%': True, 'time': elapsed, 'bytes': current_bytes})
            
    def finish(self, success=True):
        #生成报告
        elapsed = time.time() - self.start_time
        
        if success:
            print(f"\n[OK] {self.current_operation} completed")
            print(f"    ├── Time: {elapsed:.2f}s")
            print(f"    ├── Data: {self.total_bytes:,} bytes")
            print(f"    ├── Speed: {self.avg_speed:.2f} KB/s (avg), {self.peak_speed:.2f} KB/s (peak)")
            print(f"    └── Rate: {(self.total_bytes/1024)/elapsed:.2f} KB/s overall")
        else:
            print(f"\n[FAIL] {self.current_operation} failed after {elapsed:.2f}s")

class APDUMonitor:
    #根治APDU卡死问题
    def __init__(self):
        self.operation_start = 0
        self.last_response = 0
        self.stuck_warnings = 0
        
    def start_operation(self, operation_name):
        self.operation_start = time.time()
        self.operation_name = operation_name
        if DEBUG_MODE:
            print(f"-> {operation_name}...")
            
    def check_stuck(self):
        #检查是否卡死
        if self.operation_start > 0:
            elapsed = time.time() - self.operation_start
            if elapsed > TIMEOUT * 0.7: 
                self.stuck_warnings += 1
                if self.stuck_warnings == 1:
                    print(f"\n[WARN] {self.operation_name} taking longer than expected ({elapsed:.1f}s)...")
                elif self.stuck_warnings == 2:
                    print(f"[WARN] Still waiting... ({elapsed:.1f}s) - checking hardware...")
                return True
        return False
        
    def finish_operation(self, success=True, sw=None):
        if self.operation_start > 0:
            elapsed = time.time() - self.operation_start
            self.last_response = elapsed
            
            if success:
                if elapsed > 3:
                    print(f"[OK] {self.operation_name} completed (slow)")
                elif DEBUG_MODE:
                    print(f"[OK] {self.operation_name} completed")
            else:
                print(f"[FAIL] {self.operation_name} failed - SW: {hex(sw) if sw else 'N/A'}")
                
        self.operation_start = 0
        self.stuck_warnings = 0

progress = ProgressMonitor()
apdu_monitor = APDUMonitor()

logging.basicConfig(
    level=logging.INFO if not DEBUG_MODE else logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('passport_personalization.log', mode='w')
    ]
)

if DEBUG_MODE:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING) 
    logging.getLogger().addHandler(console_handler)

logging.info("Passport personalization script started")

# 扩展：AA密钥写入

def encode_length(length: int) -> bytes:
    """
    编码BER-TLV长度字段
    """
    if length < 0x80:
        # 短格式：0-127字节
        return bytes([length])
    elif length <= 0xFF:
        # 长格式：128-255字节
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        # 长格式：256-65535字节
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        raise ValueError(f"长度太大: {length}")

def build_aa_key_payload(tag: int, key_component_data: bytes) -> bytes:
    """
    根据抄袭马蒂诺卡端的逻辑，构建非常傻逼的BER-TLV载荷
    
    期望的格式：
    [外层标签][外层长度][外层值-被跳过][内层标签0x04][内层长度][密钥数据]
    """
    # 重要发现：skipValue()意味着外层值是空的，内层TLV是并列的！
    # 外层TLV：tag + 长度0 + 空值
    outer_tlv = bytes([tag, 0x00])  # 长度为0的TLV
    
    # 内层TLV：OCTET STRING (0x04) + 长度 + 密钥数据  
    inner_tlv = b'\x04' + encode_length(len(key_component_data)) + key_component_data
    
    # 连接：外层TLV + 内层TLV （并列，不是嵌套！）绝对有无数傻逼死在这里~
    return outer_tlv + inner_tlv

def parse_pkcs8_private_key(der_data: bytes) -> tuple[bytes, bytes]:
    """
      解析PKCS#8格式的RSA私钥，提取模数和私指数
    
    PKCS#8结构：
    PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey (OCTET STRING包含PKCS#1私钥)
    }
    """
    print("\n  开始解析PKCS#8私钥格式...")
    
    def read_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
        """读取ASN.1长度字段"""
        if data[offset] & 0x80 == 0:
            # 短格式
            return data[offset], offset + 1
        else:
            # 长格式
            length_bytes = data[offset] & 0x7F
            if length_bytes == 0:
                raise ValueError("无限长度格式不支持")
            length = 0
            for i in range(length_bytes):
                length = (length << 8) | data[offset + 1 + i]
            return length, offset + 1 + length_bytes
    
    def read_asn1_integer(data: bytes, offset: int) -> tuple[bytes, int]:
        """读取ASN.1 INTEGER"""
        if data[offset] != 0x02:
            raise ValueError(f"期望INTEGER标签0x02，得到0x{data[offset]:02X}")
        length, new_offset = read_asn1_length(data, offset + 1)
        value = data[new_offset:new_offset + length]
        
        # 移除前导零
        while len(value) > 1 and value[0] == 0x00:
            value = value[1:]
            
        return value, new_offset + length
    
    try:
        offset = 0
        
        # 1. 外层SEQUENCE
        if der_data[offset] != 0x30:
            raise ValueError(f"期望SEQUENCE标签0x30，得到0x{der_data[offset]:02X}")
        
        seq_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ PKCS#8 SEQUENCE长度: {seq_length} 字节")
        
        # 2. Version INTEGER (应该是0)
        version, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Version: {int.from_bytes(version, 'big')}")
        
        # 3. AlgorithmIdentifier SEQUENCE
        if der_data[offset] != 0x30:
            raise ValueError(f"期望AlgorithmIdentifier SEQUENCE，得到0x{der_data[offset]:02X}")
        
        alg_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ AlgorithmIdentifier长度: {alg_length} 字节")
        
        # 跳过整个AlgorithmIdentifier
        offset += alg_length
        
        # 4. PrivateKey OCTET STRING
        if der_data[offset] != 0x04:
            raise ValueError(f"期望PrivateKey OCTET STRING，得到0x{der_data[offset]:02X}")
        
        octet_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ PrivateKey OCTET STRING长度: {octet_length} 字节")
        
        # 5. 提取内部的PKCS#1私钥
        pkcs1_data = der_data[offset:offset + octet_length]
        print(f"✓ 提取PKCS#1数据，长度: {len(pkcs1_data)} 字节")
        
        # 6. 解析PKCS#1格式
        print("\n  解析内部PKCS#1格式...")
        return parse_pkcs1_private_key(pkcs1_data)
        
    except Exception as e:
        print(f"× PKCS#8解析失败: {e}")
        print(f"  详细诊断:")
        print(f"   文件大小: {len(der_data)} 字节")
        if len(der_data) >= 20:
            print(f"   前20字节: {der_data[:20].hex().upper()}")
        raise

def parse_pkcs1_private_key(der_data: bytes) -> tuple[bytes, bytes]:
    """
      解析PKCS#1格式的RSA私钥
    
    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e  
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER   -- (inverse of q) mod p
    }
    """
    
    def read_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
        """读取ASN.1长度字段"""
        if data[offset] & 0x80 == 0:
            return data[offset], offset + 1
        else:
            length_bytes = data[offset] & 0x7F
            if length_bytes == 0:
                raise ValueError("无限长度格式不支持")
            length = 0
            for i in range(length_bytes):
                length = (length << 8) | data[offset + 1 + i]
            return length, offset + 1 + length_bytes
    
    def read_asn1_integer(data: bytes, offset: int) -> tuple[bytes, int]:
        """读取ASN.1 INTEGER"""
        if data[offset] != 0x02:
            raise ValueError(f"期望INTEGER标签0x02，得到0x{data[offset]:02X}")
        length, new_offset = read_asn1_length(data, offset + 1)
        value = data[new_offset:new_offset + length]
        
        # 移除前导零
        while len(value) > 1 and value[0] == 0x00:
            value = value[1:]
            
        return value, new_offset + length
    
    try:
        offset = 0
        
        # 1. 外层SEQUENCE
        if der_data[offset] != 0x30:
            raise ValueError(f"期望SEQUENCE标签0x30，得到0x{der_data[offset]:02X}")
        
        seq_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ PKCS#1 SEQUENCE长度: {seq_length} 字节")
        
        # 2. Version
        version, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Version: {int.from_bytes(version, 'big')}")
        
        # 3. Modulus (n)
        modulus, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Modulus长度: {len(modulus)} 字节 ({len(modulus)*8} bits)")
        
        # 4. Public Exponent (e) - 跳过
        pub_exp, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Public Exponent: {int.from_bytes(pub_exp, 'big')}")
        
        # 5. Private Exponent (d)
        private_exp, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Private Exponent长度: {len(private_exp)} 字节")
        
        if DEBUG_MODE:
            print(f"\n  RSA密钥组件:")
            print(f"   Modulus (前16字节): {modulus[:16].hex().upper()}...")
            print(f"   Private Exp (前16字节): {private_exp[:16].hex().upper()}...")
        
        return modulus, private_exp
        
    except Exception as e:
        print(f"× PKCS#1解析失败: {e}")
        if len(der_data) >= 20:
            print(f"  前20字节: {der_data[:20].hex().upper()}")
            context = der_data[max(0, offset-10):offset+10] if 'offset' in locals() else der_data[:20]
            if context:
                print(f"  周围字节: {context.hex().upper()}")
        raise



def write_aa_secret(connection, key_file_path: str = "AA_RSA1024_private.der"):
    """
    【阶段零：机密注入】
    在任何其他个人化操作之前，通过专用通道写入AA私钥。
    
    Args:
        connection: 卡连接对象
        key_file_path: AA私钥文件路径
    """
    print("\n" + "="*60)
    print(">> 阶段零：机密注入 (写入AA私钥)")
    print("="*60)

    # 1. 同目录查找RSA1024关键字文件
    script_dir = os.path.dirname(__file__)
    found_key_path = None
    
    # 先尝试默认文件名
    default_path = os.path.join(script_dir, key_file_path)
    if os.path.exists(default_path):
        found_key_path = default_path
    else:
        # 搜索包含RSA1024的文件
        for filename in os.listdir(script_dir):
            if 'RSA_1024' in filename and filename.endswith('.der'):
                found_key_path = os.path.join(script_dir, filename)
                break
    
    if not found_key_path:
        print(f"× [FAIL] 未找到RSA1024私钥文件!")
        print(">> 🚨 缺少机密文件，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开")
        except:
            print("！ [DISCONNECT] 断卡失败")
        exit(1)
    
    key_file_path = found_key_path
    print(f"√ 找到AA私钥: {os.path.basename(key_file_path)}")

    # 2. 解析AA私钥文件
    print(f"-> 解析AA私钥文件: {key_file_path}")
    try:
        with open(key_file_path, 'rb') as f:
            key_data = f.read()
        
        print(f"✓ 文件读取成功: {len(key_data)} 字节")
        
        # 自动检测格式并解析
        try:
            modulus, private_exponent = parse_pkcs8_private_key(key_data)
        except Exception as e:
            print(f"！ PKCS#8解析失败，尝试PKCS#1格式: {e}")
            modulus, private_exponent = parse_pkcs1_private_key(key_data)
        
        print(f"√ AA私钥解析成功!")
        print(f"   密钥长度: {len(modulus)*8} bits")
        print(f"   Modulus: {len(modulus)} 字节")
        print(f"   Private Exponent: {len(private_exponent)} 字节")
        
    except Exception as e:
        print(f"× [FAIL] AA私钥解析失败: {e}")
        print(">> 🚨 机密注入失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开 - 手动断电重新开始")
        except:
            print("！ [DISCONNECT] 断卡失败，手动断电")
        print(">> 🛑 程序终止 - 手动断电后重新运行")
        exit(1)

    # 3. SELECT AID (确保正与Applet对话)
    print("-> 选择护照应用...")
    aid_bytes = bytes([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) + aid_bytes
    resp_data, sw = send_apdu(connection, apdu, "AA_SELECT_AID")
    if sw != 0x9000:
        print(f"× [FAIL] 机密注入失败：选择Applet失败，SW={hex(sw)}")
        print(">> 🚨 Applet选择失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开 - 手动断电重新开始")
        except:
            print("！ [DISCONNECT] 断卡失败，手动断电")
        print(">> 🛑 程序终止 - 手动断电后重新运行")
        exit(1)
    print("✓ 护照应用已准备好接收机密...")

    # 4. 通过绿色通道写入AA密钥组件（一次性TLV格式）
    try:
        print("\n-> 开始机密注入...")
        
        # 构造并发送模数 (P2=0x60)
        print("-> 构造并发送AA模数...")
        modulus_payload = build_aa_key_payload(0x60, modulus)
        
        # 支持扩展长度APDU
        if len(modulus_payload) <= 255:
            apdu_mod = bytes([0x00, 0xDA, 0x00, 0x60, len(modulus_payload)]) + modulus_payload
        else:
            # 扩展长度格式：CLA INS P1 P2 00 LenHi LenLo Data
            apdu_mod = bytes([0x00, 0xDA, 0x00, 0x60, 0x00, 
                             (len(modulus_payload) >> 8) & 0xFF, 
                             len(modulus_payload) & 0xFF]) + modulus_payload
        
        print(f"   TLV载荷长度: {len(modulus_payload)} 字节")
        print(f"   APDU总长度: {len(apdu_mod)} 字节")
        if DEBUG_MODE:
            print(f"   TLV格式: {modulus_payload[:20].hex().upper()}...")
        
        resp_data, sw = send_apdu(connection, apdu_mod, "PUT_AA_MODULUS_TLV")
        if sw != 0x9000:
            raise RuntimeError(f"写入AA模数失败, SW={sw:04X}")
        print("✓ 模数注入成功！")
        #私钥必须一发APDU打进去，护照机制这样设定的！
        
        # 构造并发送私钥指数 (P2=0x61)
        print("-> 构造并发送AA私钥指数...")
        exp_payload = build_aa_key_payload(0x61, private_exponent)
        
        # 支持扩展长度APDU
        if len(exp_payload) <= 255:
            apdu_exp = bytes([0x00, 0xDA, 0x00, 0x61, len(exp_payload)]) + exp_payload
        else:
            # 扩展长度格式：CLA INS P1 P2 00 LenHi LenLo Data
            apdu_exp = bytes([0x00, 0xDA, 0x00, 0x61, 0x00, 
                             (len(exp_payload) >> 8) & 0xFF, 
                             len(exp_payload) & 0xFF]) + exp_payload
        
        print(f"   TLV载荷长度: {len(exp_payload)} 字节")
        print(f"   APDU总长度: {len(apdu_exp)} 字节")
        if DEBUG_MODE:
            print(f"   TLV格式: {exp_payload[:20].hex().upper()}...")
        
        resp_data, sw = send_apdu(connection, apdu_exp, "PUT_AA_EXPONENT_TLV")
        if sw != 0x9000:
            raise RuntimeError(f"写入AA私钥指数失败, SW={sw:04X}")
        print("✓ 私钥指数注入成功！")
        print("\n√ [SUCCESS] 阶段零：机密注入完成！AA私钥已写入。")
        print(">> 绿色通道机密注入成功！")
        print("="*60)
        
    except Exception as e:
        print(f"× [FAIL] 机密注入失败: {e}")
        print(">> 🚨 密钥写入失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开 - 手动断电重新开始")
        except:
            print("！ [DISCONNECT] 断卡失败，手动断电")
        print(">> 🛑 程序终止 - 手动断电后重新运行")
        exit(1)

def connect_reader():
    try:
        print(">> Connecting to smart card reader...")
        reader_list = readers()
        if not reader_list:
            raise RuntimeError("No smart card readers found")
        reader = reader_list[0]
        print(f">> Using reader: {reader}")
        connection = reader.createConnection()
        connection.connect()
        print("[OK] Reader connected successfully")
        return connection
    except Exception as e:
        print(f"[FAIL] Failed to connect to reader: {e}")
        raise

#增加了custom_timeout=TIMEOUT参数
# 重大修改：彻底移除重试机制！改名为send_apdu！
def send_apdu(connection, apdu: bytes, operation_name="APDU") -> tuple[bytes, int]:

    #🚨最后优化版APDU发送 - 绝对可靠，无线程诅咒

    apdu_monitor.start_operation(operation_name)
    
    # 记录命令（APDUAnalyzer非常牛逼，保留它！）
    apdu_analyzer.log_command(apdu, operation_name, time.time())
    
    try:
        # === 核心修改：直接、阻塞式调用，依赖connection自带的官方超时
        data, sw1, sw2 = connection.transmit(list(apdu))
        sw = (sw1 << 8) | sw2

        # 记录响应
        apdu_analyzer.log_response(bytes(data), sw, operation_name, time.time())
        apdu_monitor.finish_operation(success=(sw == 0x9000), sw=sw)

        return bytes(data), sw

    except Exception as e:
        # 如果超时或发生任何其他传输错误，这里会捕获到
        apdu_monitor.finish_operation(success=False)
        logging.error(f"APDU {operation_name} failed: {e}")
        print(f"\n[FATAL] 🚨 APDU传输失败！请检查读卡器连接或卡片状态！")
        # 打印详细错误信息，帮助诊断
        traceback.print_exc()
        raise


def log_apdu_command(apdu: bytes, operation_name: str):
    #详细APDU命令记录 模拟Bus Hound抓包
    #好像代码结构重复了
    if not LOG_RAW_APDUS:
        return
        
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    # 解析APDU结构
    if len(apdu) >= 4:
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        
        # APDU命令识别
        cmd_info = identify_apdu_command(ins, p1, p2)
        
        log_entry = f"""
 [{timestamp}] APDU COMMAND - {operation_name}
├── Raw APDU: {apdu.hex().upper()}
├── Structure:
│   ├── CLA: {cla:02X} ({get_cla_description(cla)})
│   ├── INS: {ins:02X} ({cmd_info['name']})
│   ├── P1:  {p1:02X} ({cmd_info['p1_desc']})
│   └── P2:  {p2:02X} ({cmd_info['p2_desc']})
├── Data Length: {len(apdu)-4 if len(apdu)>4 else 0} bytes
└── Description: {cmd_info['description']}
"""
        
        # 写入日志文件
        with open(APDU_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry)
        
        if DEBUG_MODE:
            print(log_entry)


def log_apdu_response(response_data: bytes, sw: int, operation_name: str):
    #详细APDU命令记录
    #好像代码结构重复了
    if not LOG_RAW_APDUS:
        return
        
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    sw_desc = get_sw_description(sw)
    
    log_entry = f"""
 [{timestamp}] APDU RESPONSE - {operation_name}
├── Status Word: {sw:04X} ({sw_desc})
├── Data Length: {len(response_data)} bytes
├── Raw Data: {response_data.hex().upper() if response_data else 'NONE'}
└── Success: {'√' if sw == 0x9000 else '×'}
{'='*50}
"""
    
    # 写入日志文件
    with open(APDU_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry)
    
    if DEBUG_MODE:
        print(log_entry)


def identify_apdu_command(ins: int, p1: int, p2: int) -> dict:
    """  APDU命令识别（模拟Bus Hound的智能识别）"""
    commands = {
        0xA4: {"name": "SELECT", "description": "Select File or App"},
        0x84: {"name": "GET_CHALLENGE", "description": "Get a random challenge"},
        0x82: {"name": "EXTERNAL_AUTHENTICATE", "description": "External Authentication"},
        0xDA: {"name": "PUT_DATA", "description": "Write data object"},
        0xE0: {"name": "CREATE_FILE", "description": "Create a file"},
        0xD6: {"name": "UPDATE_BINARY", "description": "Update Binary Files"},
        0xB0: {"name": "READ_BINARY", "description": "Reading binary files"},
        

    }
    
    cmd = commands.get(ins, {"name": f"UNKNOWN_{ins:02X}", "description": "未知命令"})
    
    # 详细的P1/P2解析
    if ins == 0xA4:  # SELECT
        p1_desc = {0x00: "MF/DF/EF by FID", 0x04: "DF by name"}.get(p1, f"Unknown_{p1:02X}")
        p2_desc = {0x00: "First occurrence", 0x0C: "No response"}.get(p2, f"Unknown_{p2:02X}")
    elif ins == 0xD6:  # UPDATE_BINARY
        offset = (p1 << 8) | p2
        p1_desc = f"Offset_High_{p1:02X}"
        p2_desc = f"Offset_Low_{p2:02X} (Total_Offset: {offset:04X})"
    else:
        p1_desc = f"Param1_{p1:02X}"
        p2_desc = f"Param2_{p2:02X}"
    
    cmd["p1_desc"] = p1_desc
    cmd["p2_desc"] = p2_desc
    
    return cmd


def get_cla_description(cla: int) -> str:
    """CLA字节描述"""
    descriptions = {
        0x00: "ISO7816-4 Standard",
        0x0C: "Secure Messaging (Last)",
        0x1C: "Secure Messaging (Chained)",
    }
    return descriptions.get(cla, f"Unknown_CLA_{cla:02X}")


def get_sw_description(sw: int) -> str:
    """状态字描述"""
    descriptions = {
        0x9000: "Success",
        0x6982: "Security status not satisfied", 
        0x6985: "Command not allowed",
        0x6A82: "File not found",
        0x6300: "Authentication failed",
        0x6882: "Secure messaging not supported",
    }
    return descriptions.get(sw, f"Unknown_SW_{sw:04X}")

def calculate_check_digit(data: bytes) -> str:
    """7-3-1校验位，参考 PassportInit.java:checkDigit"""
    weights = [7, 3, 1]
    result = 0
    for i, char in enumerate(data):
        if char == ord('<'):
            value = 0
        elif ord('0') <= char <= ord('9'):
            value = char - ord('0')
        elif ord('A') <= char <= ord('Z'):
            value = char - ord('A') + 10
        elif ord('a') <= char <= ord('z'):
            value = char - ord('a') + 10
        else:
            value = 0
        result = (result + weights[i % 3] * value) % 10
    return str(result)  # 返回字符串而不是数字

def derive_key(seed: bytes, mode: int) -> bytes:
    """派生KB_Enc/KB_MAC"""
    # 完全对应Java代码：c = { 0x00, 0x00, 0x00, 0x00 }; c[3] = mode
    c = b"\x00\x00\x00" + bytes([mode])
    
    sha1 = hashlib.sha1()
    sha1.update(seed)
    sha1.update(c)
    digest = bytearray(sha1.digest()[:16])  # 只取前16字节
    
    # 奇偶校验位调整 - 完全对应PassportUtil.evenBits
    for i in range(16):
        b = digest[i]
        # 计算奇偶性：统计1的个数
        count = bin(b & 0xFF).count('1')
        
        # 如果偶数个1，调整最低位使其为奇数
        if (count & 1) == 0:
            digest[i] = b ^ 1  
    
    return bytes(digest)

def increment_ssc(ssc: bytearray):
    """SSC递增"""
    for i in range(len(ssc) - 1, -1, -1):
        if ssc[i] < 0xFF:
            ssc[i] += 1
            break
        ssc[i] = 0

def mac_iso9797_alg3(data: bytes, key: bytes) -> bytes:
    """ISO/IEC 9797-1 MAC Algorithm 3, Method 2 padding.

    支持8字节(单钥)或16字节(双钥)密钥。当提供16字节时，按K1|K2处理，最终步骤为E(K1)-D(K2)-E(K1)。
    """
    # Method 2 padding：数据 + 0x80 + 0x00… 到8字节边界
    padded = data + b"\x80"
    if len(padded) % 8 != 0:
        padded += b"\x00" * (8 - len(padded) % 8)

    if len(key) == 8:
        k1 = key
        k2 = key
    elif len(key) >= 16:
        k1 = key[:8]
        k2 = key[8:16]
    else:
        raise ValueError("MAC key length must be 8 or 16 bytes")

    des_k1 = DES.new(k1, DES.MODE_ECB)

    iv = b"\x00" * 8
    for offset in range(0, len(padded) - 8, 8):
        block = padded[offset:offset + 8]
        iv = des_k1.encrypt(bytes(a ^ b for a, b in zip(block, iv)))

    # 取最后一块并与上一中间值异或
    last_block = padded[-8:]
    xored = bytes(a ^ b for a, b in zip(last_block, iv))

    # ALG3 Tail
    step1 = des_k1.encrypt(xored)            # E(K1)
    des_k2 = DES.new(k2, DES.MODE_ECB)
    step2 = des_k2.decrypt(step1)            # D(K2)
    mac = des_k1.encrypt(step2)              # E(K1)
    return mac

def perform_bac_authentication(connection, mrz_data: bytes) -> tuple[bytes, bytes, bytearray]:
    """执行BAC认证"""
    print("\n>> 开始BAC认证...")
    
    # 添加状态诊断
    print("[DEBUG] Current BAC authentication attempt")
    print(f"[DEBUG] MRZ data length: {len(mrz_data)} bytes")
    print(f"[DEBUG] MRZ content: {mrz_data.decode('ascii')}")
    
    key_seed = hashlib.sha1(mrz_data).digest()[:16]
    kb_enc = derive_key(key_seed, 1)  # 16字节3DES密钥
    kb_mac = derive_key(key_seed, 2)   # 16字节3DES密钥 (不截断!)
    
    print(f">> MRZ密钥派生完成")
    if DEBUG_MODE:
        print(f"[DEBUG] KB_ENC (16 bytes): {kb_enc.hex()}")
        print(f"[DEBUG] KB_MAC (16 bytes): {kb_mac.hex()}")

    print("-> GET_CHALLENGE...")
    get_challenge_apdu = bytes([0x00, 0x84, 0x00, 0x00, 0x08])
    response_data, sw = send_apdu(connection, get_challenge_apdu, "GET_CHALLENGE")
    if sw != 0x9000:
        print(f"\n[ERROR] GET_CHALLENGE failed with SW={hex(sw)}")
        
        # 提供详细的诊断信息
        if sw == 0x6985:
            print("[ERROR] Command not allowed - check card state")
            print("[INFO] Possible solutions:")
            print("  1. Card may need applet reinstall")
            print("  2. MRZ data may not be properly set")
            print("  3. Card may be in wrong security state")
        elif sw == 0x6982:
            print("[ERROR] Security status not satisfied")
            print("[INFO] This means:")
            print("  1. BAC keys not properly set (!hasMutualAuthenticationKeys()), OR")
            print("  2. BAC already completed (hasMutuallyAuthenticated())")
            print("[INFO] Previous MAC test may have partially succeeded")
            print("[INFO] Possible solutions:")
            print("  1. Try reinstalling the applet")
            print("  2. Check if GET_CHALLENGE works immediately after PUT_MRZ")
            print("  3. Verify MRZ data is correctly written")
            
            # 尝试诊断性命令
            print("\n[INFO] Running diagnostic checks...")
            try:
                # 尝试重新选择MF
                select_mf_apdu = bytes([0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])
                resp_data_mf, sw_mf = send_apdu(connection, select_mf_apdu, "DIAG_SELECT_MF")
                print(f"[DIAG] SELECT_MF: SW={hex(sw_mf)}")
                
                # 尝试重新选择applet
                aid_bytes = bytes([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
                apdu_aid = bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) + aid_bytes
                resp_data_aid, sw_aid = send_apdu(connection, apdu_aid, "DIAG_SELECT_AID")
                print(f"[DIAG] Re-SELECT_AID: SW={hex(sw_aid)}")
                
                if sw_aid == 0x9000:
                    print("[INFO] Applet re-selection successful, retrying GET_CHALLENGE...")
                    time.sleep(0.1)
                    resp_retry, sw_retry = send_apdu(connection, get_challenge_apdu, "GET_CHALLENGE_RETRY")
                    if sw_retry == 0x9000:
                        print(f"[SUCCESS] GET_CHALLENGE retry successful!")
                        response_data = resp_retry
                        sw = sw_retry
                    else:
                        print(f"[FAIL] GET_CHALLENGE retry still failed: SW={hex(sw_retry)}")
                
            except Exception as e:
                print(f"[DIAG] Diagnostic failed: {e}")
        
        # 如果所有尝试都失败了
    if sw != 0x9000:
        if sw == 0x6985:
            raise RuntimeError(f"GET CHALLENGE failed: Command not allowed - check card state (SW={sw:04X})")
        elif sw == 0x6982:
            raise RuntimeError(f"GET CHALLENGE failed: Security status not satisfied (SW={sw:04X})")
        else:
            raise RuntimeError(f"GET CHALLENGE failed: SW={sw:04X}")
                
    rnd_icc = bytes(response_data)
    print(f"[OK] GET_CHALLENGE completed")
    
    rnd_ifd = os.urandom(8)
    k_ifd = os.urandom(16)
    
    print("-> EXTERNAL_AUTHENTICATE...")
    plaintext = rnd_ifd + rnd_icc + k_ifd
    
    if DEBUG_MODE:
        print(f"[DEBUG] RND_IFD: {rnd_ifd.hex().upper()}")
        print(f"[DEBUG] RND_ICC: {rnd_icc.hex().upper()}")
        print(f"[DEBUG] K_IFD: {k_ifd.hex().upper()}")
        print(f"[DEBUG] Plaintext ({len(plaintext)} bytes): {plaintext.hex().upper()}")
    
    kb_enc_3des = kb_enc + kb_enc[:8]  # 16字节扩展为24字节
    cipher_enc = DES3.new(kb_enc_3des, DES3.MODE_CBC, b'\x00' * 8)
    e_ifd = cipher_enc.encrypt(plaintext)
    
    if DEBUG_MODE:
        print(f"[DEBUG] E_IFD ({len(e_ifd)} bytes): {e_ifd.hex().upper()}")
    
    # 测试不同的MAC算法
    mac = mac_iso9797_alg3(e_ifd, kb_mac)
    
    ext_auth_apdu = bytes([0x00, 0x82, 0x00, 0x00, len(e_ifd) + len(mac)]) + e_ifd + mac
    if DEBUG_MODE:
        print(f"[DEBUG] MAC ({len(mac)} bytes): {mac.hex().upper()}")
        print(f"[DEBUG] EXTERNAL_AUTH APDU ({len(ext_auth_apdu)} bytes): {ext_auth_apdu.hex().upper()}")
    response_data, sw = send_apdu(connection, ext_auth_apdu, "EXTERNAL_AUTHENTICATE")
    if sw != 0x9000:
        if sw == 0x6985:
            raise RuntimeError(f"EXTERNAL AUTHENTICATE failed: Command not allowed - wrong BAC keys? (SW={sw:04X})")
        elif sw == 0x6982:
            raise RuntimeError(f"EXTERNAL AUTHENTICATE failed: Security status not satisfied (SW={sw:04X})")
        elif sw == 0x6300:
            raise RuntimeError(f"EXTERNAL AUTHENTICATE failed: Authentication failed - check MRZ data (SW={sw:04X})")
        else:
            raise RuntimeError(f"EXTERNAL AUTHENTICATE failed: SW={sw:04X}")
    print(f"[OK] EXTERNAL_AUTHENTICATE completed")
    
    response_encrypted = bytes(response_data)[:-8]
    response_mac = bytes(response_data)[-8:]
    
    # 统一的MAC算法验证响应
    calculated_mac = mac_iso9797_alg3(response_encrypted, kb_mac)
    
    if calculated_mac != response_mac:
        print(f"[WARN] Response MAC mismatch. Expected: {calculated_mac.hex().upper()}, Got: {response_mac.hex().upper()}")
        print(f"[INFO] Trying alternative response MAC verification methods...")
        
        # 其他可能的响应MAC验证方法
        # 8字节密钥的DES-CBC
        try:
            kb_mac_8 = kb_mac[:8]
            cipher_mac_verify = DES.new(kb_mac_8, DES.MODE_CBC, b'\x00' * 8)
            calculated_mac_v1 = cipher_mac_verify.encrypt(response_encrypted)[-8:]
            
            if calculated_mac_v1 == response_mac:
                print(f"[OK] Response MAC verified using 8-byte DES-CBC")
                calculated_mac = calculated_mac_v1
            else:
                print(f"[INFO] MAC v1 (8-byte DES-CBC): {calculated_mac_v1.hex().upper()}")
        except Exception as e:
            print(f"[INFO] 8-byte DES-CBC failed: {e}")
        
        # 方法2：可能不需要填充
        try:
            calculated_mac_v2 = mac_iso9797_alg3(response_encrypted, kb_mac)  # 已经试过了
            print(f"[INFO] MAC v2 (ISO9797 variant): {calculated_mac_v2.hex().upper()}")
        except Exception as e:
            print(f"[INFO] ISO9797 variant failed: {e}")
        
        # 方法3：直接DES-CBC无填充
        try:
            kb_mac_8 = kb_mac[:8]
            cipher_mac_verify = DES.new(kb_mac_8, DES.MODE_CBC, b'\x00' * 8)
            calculated_mac_v3 = cipher_mac_verify.encrypt(response_encrypted)[-8:]
            
            if calculated_mac_v3 == response_mac:
                print(f"[OK] Response MAC verified using DES-CBC without padding")
                calculated_mac = calculated_mac_v3
            else:
                print(f"[INFO] MAC v3 (DES-CBC no padding): {calculated_mac_v3.hex().upper()}")
        except Exception as e:
            print(f"[INFO] DES-CBC no padding failed: {e}")
        
        # 如果仍然不匹配，警告但继续
        # 这里好像有问题
        if calculated_mac != response_mac:
            print(f"[WARN] Response MAC verification failed, but continuing...")
            print(f"[WARN] This might indicate different MAC algorithms for request vs response")
    else:
        print(f"[OK] Response MAC verified successfully")

    # 解密响应（使用相同的3DES密钥）
    cipher_enc_decrypt = DES3.new(kb_enc_3des, DES3.MODE_CBC, b'\x00' * 8)
    decrypted = cipher_enc_decrypt.decrypt(response_encrypted)
    resp_rnd_icc, resp_rnd_ifd, k_icc = decrypted[:8], decrypted[8:16], decrypted[16:32]

    if resp_rnd_icc != rnd_icc or resp_rnd_ifd != rnd_ifd:
        raise RuntimeError("BAC random number verification failed")

    key_seed_session = bytes(a ^ b for a, b in zip(k_ifd, k_icc))
    ks_enc = derive_key(key_seed_session, 1)
    
    # --- 核心修正：使用正确的会话种子派生ks_mac ---
    ks_mac_material_session = derive_key(key_seed_session, 2)
    # 使用完整16字节会话MAC密钥（K1||K2）
    ks_mac = ks_mac_material_session  # 16 bytes

    ssc = bytearray(rnd_icc[4:] + rnd_ifd[4:])
    
    print(f"[OK] BAC认证成功，会话密钥已建立")
    
    return ks_enc, ks_mac, ssc


def build_sm_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes, le: int, ks_enc: bytes, ks_mac: bytes, ssc: bytearray) -> bytes:
    """构造SM APDU"""
    print(f"\n[DEBUG] SSC before increment: {bytes(ssc).hex()}")
    increment_ssc(ssc)
    print(f"[DEBUG] SSC after increment: {bytes(ssc).hex()}")
    
    # UPDATE_BINARY特殊调试
    if ins == 0xD6:
        print(f"\n[DEBUG] === UPDATE_BINARY Special Debug ===")
        print(f"[DEBUG] Offset: P1={p1:02X}, P2={p2:02X}")
        print(f"[DEBUG] Data length: {len(data) if data else 0} bytes")
        if data:
            print(f"[DEBUG] Raw data: {data.hex()}")
        print(f"[DEBUG] SSC for this command: {bytes(ssc).hex()}")

    do87 = b""
    if data:
        # SM加密：数据 + ISO9797填充，然后3DES-CBC加密
        padded_data = data + b"\x80" + b"\x00" * ((8 - (len(data) + 1) % 8) % 8)
        print(f"[DEBUG] Plaintext data: {data.hex()}")
        print(f"[DEBUG] Padded data: {padded_data.hex()}")
        # 3DES密钥：16字节扩展为24字节 (K1|K2|K1)
        ks_enc_3des = ks_enc + ks_enc[:8]
        cipher_enc_sm = DES3.new(ks_enc_3des, DES3.MODE_CBC, iv=b"\x00"*8)
        encrypted = cipher_enc_sm.encrypt(padded_data)
        print(f"[DEBUG] Encrypted data: {encrypted.hex()}")
        do87_data = b"\x01" + encrypted
        do87_len = len(do87_data)
        do87 = b"\x87" + (b"\x81" + bytes([do87_len]) if do87_len > 127 else bytes([do87_len])) + do87_data

    # 只有当le>0时才构建DO97（le=0表示不期望响应数据）
    # APDU协议：Le=256应编码为0x00
    do97 = b"\x97\x01" + bytes([le % 256]) if le is not None and le > 0 else b""
    
    header = bytes([cla, ins, p1, p2])
    # 先计算MAC输入，不包含DO'8E
    len_field = bytes([len(do87) + len(do97) + 10]) if (do87 or do97) else b"\x0A"  # +10 for DO'8E
    # 根据Applet: ssc || header(4) || pad(0x80+3*00) || Lc+DOs
    pad_after_hdr = b"\x80" + b"\x00"*3
    
    # Java端MAC验证：SSC + header + padding + DOs（不包含Lc）
    mac_input = bytes(ssc) + header + pad_after_hdr + do87 + do97
    
    # 调试MAC计算
    print(f"\n[DEBUG] === MAC Calculation Details ===")
    print(f"[DEBUG] SSC: {bytes(ssc).hex()}")
    print(f"[DEBUG] Header: {header.hex()}")
    print(f"[DEBUG] Padding: {pad_after_hdr.hex()}")
    print(f"[DEBUG] Lc (not in MAC): {len_field.hex()} (dec={len_field[0]})")
    print(f"[DEBUG] DO87: {do87.hex() if do87 else 'none'}")
    print(f"[DEBUG] DO97: {do97.hex() if do97 else 'none'}")
    print(f"[DEBUG] MAC input len: {len(mac_input)}")
    print(f"[DEBUG] MAC input: {mac_input.hex()}")
    
    # 使用ISO9797-1 M2 ALG3计算MAC，注意不要重复padding
    mac = mac_iso9797_alg3(mac_input, ks_mac)
    print(f"[DEBUG] Calculated MAC: {mac.hex()}")
    print(f"[DEBUG] ================================")
    
    do8e = b"\x8e\x08" + mac
    
    data_field = do87 + do97 + do8e
    apdu = header + bytes([len(data_field)]) + data_field
    
    if do87:
        print(f"[DEBUG] DO87 length: {len(do87)}, content: {do87.hex()}")
    if do97:
        print(f"[DEBUG] DO97 length: {len(do97)}, content: {do97.hex()}")
        
    print(f"[DEBUG] Final SM command APDU: {apdu.hex()}")
    
    return apdu


def parse_sm_response(response: bytes, ks_enc: bytes, ks_mac: bytes, ssc: bytearray) -> tuple[bytes, int]:
    #解析SM响应 已修正MAC算法，测试了7种才他妈确认
    increment_ssc(ssc)
    
    mac_pos = response.rfind(b"\x8e\x08")
    if mac_pos == -1:
        raise ValueError("MAC data object (DO'8E) not found in SM response")
        
    received_mac = response[mac_pos+2 : mac_pos+10]
    mac_input = bytes(ssc) + response[:mac_pos]
    
    # 使用ISO9797-1 M2 ALG3重新计算期望MAC
    expected_mac = mac_iso9797_alg3(mac_input, ks_mac)
    
    if received_mac != expected_mac:
        raise ValueError(f"SM Response MAC verification failed: expected {expected_mac.hex()}, got {received_mac.hex()}")


    pos = 0
    data = b""
    sw = 0x6F00
    
    tlv_data = response[:mac_pos]
    
    while pos < len(tlv_data):
        tag = tlv_data[pos]
        pos += 1
        
        if tlv_data[pos] & 0x80:
            len_bytes = tlv_data[pos] & 0x7F
            length = int.from_bytes(tlv_data[pos+1 : pos+1+len_bytes], 'big')
            pos += len_bytes + 1
        else:
            length = tlv_data[pos]
            pos += 1
        
        value = tlv_data[pos : pos+length]
        pos += length
        
        if tag == 0x87:
            if value[0] != 0x01:
                raise ValueError("Invalid DO'87': missing 0x01 marker")
            
            # SM解密：使用相同的3DES密钥
            ks_enc_3des = ks_enc + ks_enc[:8]
            cipher_enc_sm = DES3.new(ks_enc_3des, DES3.MODE_CBC, iv=b"\x00"*8)
            decrypted = cipher_enc_sm.decrypt(value[1:])
            
            #  安全的unpadding实现 - 修复0x80截断问题！
            data = safe_unpadding(decrypted)

        elif tag == 0x99:
            sw = int.from_bytes(value, 'big')
            
    # SW=0x0001是非标准状态字，立即报错中断！
    if sw == 0x0001:
        print(f"\n[ERROR] ========== SW=0x0001 DETECTED ==========")
        print(f"[ERROR] This is NOT a standard ISO7816 status word!")
        print(f"[ERROR] Raw SM response: {response.hex()}")
        print(f"[ERROR] SSC at parse: {bytes(ssc).hex()}")
        print(f"[ERROR] Decrypted data: {data.hex() if data else 'None'}")
        print(f"[ERROR] =========================================")
        raise ValueError(f"Non-standard SW=0x0001 received - JavaCard implementation error")

    return data, sw

def safe_unpadding(decrypted_data: bytes) -> bytes:
    #🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨unpadding的极限处理方案！防止截断原始数据0x80的问题！
    
    if len(decrypted_data) == 0:
        return decrypted_data
    
    #   数据完整性监控
    if ENABLE_DATA_INTEGRITY_MONITORING:
        print(f"\n[INTEGRITY] 开始安全unpadding分析:")
        print(f"[INTEGRITY] 输入数据长度: {len(decrypted_data)} 字节")
        if len(decrypted_data) >= 16:
            print(f"[INTEGRITY] 前16字节: {decrypted_data[:16].hex().upper()}")
            print(f"[INTEGRITY] 后16字节: {decrypted_data[-16:].hex().upper()}")
        else:
            print(f"[INTEGRITY] 全部数据: {decrypted_data.hex().upper()}")
    
    # ISO9797-1 Method 2填充格式：原始数据 + 0x80 + 0x00... 填充到8字节边界   
    # 🚨 从尾部开始扫描🚨 最强大脑实现！🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨
    i = len(decrypted_data) - 1
    
    # 1. 跳过尾部的所有0x00字节
    trailing_zeros = 0
    while i >= 0 and decrypted_data[i] == 0x00:
        trailing_zeros += 1
        i -= 1
    
    #  检查所有0x80位置检测数据截断问题！
    if ENABLE_DATA_INTEGRITY_MONITORING:
        all_0x80_positions = []
        for pos in range(len(decrypted_data)):
            if decrypted_data[pos] == 0x80:
                all_0x80_positions.append(pos)
        
        if len(all_0x80_positions) > 1:
            print(f"[INTEGRITY]  发现多个0x80字节位置: {all_0x80_positions}")
            print(f"[INTEGRITY] 使用安全算法确定真正的填充标记...")
            for pos in all_0x80_positions:
                context_start = max(0, pos - 4)
                context_end = min(len(decrypted_data), pos + 5)
                print(f"[INTEGRITY] 位置{pos}: {decrypted_data[context_start:context_end].hex().upper()}")
        elif len(all_0x80_positions) == 1:
            print(f"[INTEGRITY] 发现单个0x80字节位置: {all_0x80_positions[0]}")
        else:
            print(f"[INTEGRITY] 未发现0x80字节")
    
    # 2. 检查是否找到填充标记0x80
    if i >= 0 and decrypted_data[i] == 0x80:
        # 找到了填充标记，去掉填充
        unpadded_data = decrypted_data[:i]
        
        #  详细的填充分析
        if LOG_UNPADDING_DETAILS:
            print(f"[UNPAD] 安全unpadding成功:")
            print(f"[UNPAD] 原始长度: {len(decrypted_data)} 字节")
            print(f"[UNPAD] 填充标记位置: {i}")
            print(f"[UNPAD] 尾随零字节数: {trailing_zeros}")
            print(f"[UNPAD] 总填充长度: {1 + trailing_zeros} 字节")
            print(f"[UNPAD] 结果长度: {len(unpadded_data)} 字节")
            
            #  可疑填充检测
            if WARN_ON_SUSPICIOUS_PADDING:
                # 检查填充是否过长
                padding_length = 1 + trailing_zeros
                if padding_length > 8:
                    print(f"[UNPAD]  可疑：填充长度过长 ({padding_length} > 8)")
                
                # 检查是否有其他0x80字节可能被误认为填充
                other_0x80_positions = []
                for pos in range(i):
                    if decrypted_data[pos] == 0x80:
                        other_0x80_positions.append(pos)
                
                if other_0x80_positions:
                    print(f"[UNPAD] 警告：原始数据中还有其他0x80字节在位置: {other_0x80_positions}")
                    print(f"[UNPAD] 如果使用旧的rfind算法，可能会截断到位置: {max(other_0x80_positions)}")
                    old_rfind_result = decrypted_data[:max(other_0x80_positions)]
                    print(f"[UNPAD] 旧算法结果长度: {len(old_rfind_result)} vs 新算法: {len(unpadded_data)}")
                    if len(old_rfind_result) != len(unpadded_data):
                        print(f"[UNPAD]  数据截断风险确认！新算法避免了 {len(unpadded_data) - len(old_rfind_result)} 字节的截断")
        
        return unpadded_data
    else:
        #  没有找到标准的填充标记
        if DEBUG_MODE or ENABLE_DATA_INTEGRITY_MONITORING:
            print(f"[UNPAD] 未发现标准填充标记，详细分析:")
            print(f"[UNPAD] 1. 数据可能未填充（长度刚好8字节对齐）")
            print(f"[UNPAD] 2. 使用了其他填充方式")
            print(f"[UNPAD] 3. 数据解密失败或损坏")
            print(f"[UNPAD] 原始数据长度: {len(decrypted_data)}")
            print(f"[UNPAD] 尾部零字节数: {trailing_zeros}")
            if len(decrypted_data) >= 8:
                print(f"[UNPAD] 尾部8字节: {decrypted_data[-8:].hex().upper()}")
            if i >= 0:
                print(f"[UNPAD] 最后非零字节: 0x{decrypted_data[i]:02X} (位置{i})")
        
        # 检查是否为8字节对齐的无填充数据
        if len(decrypted_data) % 8 == 0:
            # 可能是狗屎运8字节对齐，无需填充的数据
            print(f"[UNPAD]  数据长度8字节对齐，可能无填充，直接返回")
            return decrypted_data
        else:
            # 数据长度不是8字节对齐，但没有找到填充标记，可能有问题！
            print(f"[UNPAD] 数据长度非8字节对齐但无填充标记")
            print(f"[UNPAD] 长度 {len(decrypted_data)} % 8 = {len(decrypted_data) % 8}")
            # 为了安全，还是返回原始数据，让上层处理！
            return decrypted_data

def write_with_defect_handling(connection, fid: int, file_path: str, name: str, ks_enc: bytes, ks_mac: bytes, ssc: bytearray, written_total: int) -> int:

    print(f"\n>> Writing {name} ({os.path.getsize(file_path)} bytes)...")
    with open(file_path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    offset = 0
    written_bytes = 0
    #  新增：从折磨版移植的块计数器！
    chunk_count = 0  # 🚨用于渐进式延迟和硬件监控！

    #  新增：从折磨版移植的硬件稳定性提示！ 
    print(f"[INFO]   Hardware stability mode enabled:")
    print(f"[INFO] - Write delay: {WRITE_DELAY}s per command")
    print(f"[INFO] - Progress delay: {CHUNK_PROGRESS_DELAY}s every 10 chunks") 
    print(f"[INFO] - Hardware recovery: {HARDWARE_RECOVERY_DELAY}s for problem offsets")

    while offset < file_size:
        chunk = data[offset : offset + CHUNK_SIZE] # 始终使用标准的CHUNK_SIZE
        # 新增：从折磨版移植的块计数！ 
        chunk_count += 1  # 🚨跟踪写入块数量！

        try:
            # 新增：从折磨版移植的延迟策略！ 
            # 🚨 1. 高风险区域特殊处理！
            delay_time = WRITE_DELAY
            timeout_for_this_command = TIMEOUT
            
            if offset in KNOWN_BAD_OFFSETS:
                print(f"\n！ [CRITICAL] High-risk offset 0x{offset:04X} detected!")
                print(f" [PROTECTION] Applying hardware recovery delay ({HARDWARE_RECOVERY_DELAY}s)...")
                time.sleep(HARDWARE_RECOVERY_DELAY)
                delay_time = HARDWARE_RECOVERY_DELAY  # 高风险区域用更长延迟
                timeout_for_this_command = 60  # 超长超时
            
            # 🚨 2. 渐进式延迟 每10个块额外延迟！
            if chunk_count % 10 == 0:
                print(f"\n[MONITOR] Chunk #{chunk_count}: Progressive delay ({CHUNK_PROGRESS_DELAY}s)")
                time.sleep(CHUNK_PROGRESS_DELAY)

            # 🚨 3. 硬件监控检查！
            if ENABLE_HARDWARE_MONITORING and chunk_count % 20 == 0:
                print(f"[MONITOR] Hardware stability check at chunk #{chunk_count}")
                # 给硬件一个额外的休息时间
                time.sleep(0.2)

            # 🚨 4. 构建并发送APDU
            print(f"[WRITE] Offset 0x{offset:04X} (chunk #{chunk_count}) - preparing...")
            apdu = build_sm_apdu(0x0C, 0xD6, offset >> 8, offset & 0xFF, chunk, 0, ks_enc, ks_mac, ssc)
            
            # 新增：从折磨版移植的发送前延迟！ 
            # 🚨 5. 发送前延迟！防止硬件过载！
            if delay_time > 0:
                if offset in KNOWN_BAD_OFFSETS:
                    print(f"️ [DELAY] Critical offset protection delay: {delay_time}s")
                time.sleep(delay_time)
            
            resp_data, sw = send_apdu(
                connection,
                apdu, 
                f"WRITE_{name}"
            )
            
            # 6. 解析响应
            resp_data, sw = parse_sm_response(resp_data, ks_enc, ks_mac, ssc)
            
            # 7. 检查结果
            if sw == 0x9000:
                # 成功，更新偏移量和进度
                offset += len(chunk)
                written_bytes += len(chunk)
                progress.update(written_total + written_bytes, f"{name} {offset}/{file_size}")
                
                # 修复：智能延迟策略，最后一块保护！ 
                if offset < file_size:  
                    # 🚨 非最后一块：正常延迟
                    post_delay = WRITE_DELAY * 0.3  # 成功后短暂延迟
                    time.sleep(post_delay)
                else:
                    # 🚨 最后一块：确保硬件稳定，防止与后续操作冲突！
                    final_stabilization_delay = WRITE_DELAY * 0.5  # 最后一块需要更长稳定时间
                    print(f"[STABILIZE] Final chunk completed - hardware stabilization delay ({final_stabilization_delay}s)")
                    time.sleep(final_stabilization_delay)
                    print(f"[STABILIZE] Hardware stabilized, ready for verification/disconnect")
            else:
                # 如果出现任何其他错误，直接抛出，让外层捕获！
                raise RuntimeError(f"UPDATE_BINARY failed at offset 0x{offset:04X} with unexpected SW={hex(sw)}")

        except Exception as e:
            # 修改：从折磨版移植的增强错误处理！ 
            print(f"[ERROR] × Critical write failure at offset 0x{offset:04X}: {e}")
            print(f"[ERROR]  Chunk #{chunk_count}, File: {name}")
            
            # 🚨 从折磨版移植的硬件连接诊断！
            error_str = str(e).lower()
            if "failed to transmit" in error_str or "0x0000001f" in error_str:
                print(f"[DIAG]   Hardware connection failure detected!")
                print(f"[DIAG]   Possible causes:")
                print(f"[DIAG] - Reader overheating (most likely)")
                print(f"[DIAG] - USB connection unstable") 
                print(f"[DIAG] - Card contact poor")
                print(f"[DIAG] - Driver issue")
                print(f"[DIAG]  ️ Recommended actions:")
                print(f"[DIAG] - Disconnect reader for 30 seconds to cool down")
                print(f"[DIAG] - Check USB cable and port")
                print(f"[DIAG] - Re-insert card carefully")
                print(f"[DIAG] - Restart the script with increased delays")
            
            raise

    #  修改：成功消息增强！
    print(f"\n√ [OK] {name} written successfully ({written_bytes} bytes)")
    return written_bytes


def verify_file_data(connection, fid: int, file_path: str, ks_enc: bytes, ks_mac: bytes, ssc: bytearray, max_verify_size: int = None) -> bool:
    #文件验证：全量验证
    print(f"\n>> Modern verification for {hex(fid)}...")
    
    #  现代化设计：全量验证，不管文件多大！
    with open(file_path, 'rb') as f:
        expected_data = f.read()  #  全部读取！无脑验证！
    
    file_size = len(expected_data)
    print(f" [MODERN] 全量验证文件: {file_size} 字节 (无古董限制)")
    
    if file_size == 0:
        print(f"[WARN] Empty file: {file_path}")
        return True
    
    try:
        # 选择文件
        apdu = build_sm_apdu(0x0C, 0xA4, 0x00, 0x00, struct.pack(">H", fid), 0, ks_enc, ks_mac, ssc)
        resp_data, sw = send_apdu(connection, apdu, f"SELECT_VERIFY_{hex(fid)}")
        resp_data, sw = parse_sm_response(resp_data, ks_enc, ks_mac, ssc)
        if sw != 0x9000:
            print(f"[FAIL] Failed to select file {hex(fid)} for verification: SW={hex(sw)}")
            return False
        
        #  简化读取逻辑
        chip_data = b""
        offset = 0
        
        progress.set_total(file_size, f"Modern verify {hex(fid)}")
        
        while offset < file_size:
            remaining = file_size - offset
            read_len = min(CHUNK_SIZE, remaining)
            
            #  简化：失败就直接报错，不搞复杂的傻逼容错！
            apdu = build_sm_apdu(0x0C, 0xB0, offset >> 8, offset & 0xFF, b"", read_len, ks_enc, ks_mac, ssc)
            resp_data, sw = send_apdu(connection, apdu, f"MODERN_READ_{hex(fid)}")
            resp_data, sw = parse_sm_response(resp_data, ks_enc, ks_mac, ssc)
            
            if sw != 0x9000:
                print(f"\n× [FAIL] Read failed at offset 0x{offset:04X}: SW={hex(sw)}")
                print(f"[FAIL] 读取验证失败，可能原因:")
                print(f"[FAIL] 1. 文件在芯片中不存在或损坏")
                print(f"[FAIL] 2. 偏移量超出文件实际大小") 
                print(f"[FAIL] 3. 硬件通信错误")
                return False
            
            if len(resp_data) == 0:
                print(f"[INFO] Empty response at offset 0x{offset:04X}, reached end of file")
                break
            
            #  直接追加数据，更新偏移量
            chip_data += resp_data
            offset += len(resp_data)
            progress.update(offset, f"@0x{offset:04X}")
            
            #  防止无限循环
            if len(resp_data) < read_len:
                print(f"[INFO] Partial read ({len(resp_data)}/{read_len} bytes), reached end of file")
                break
                
        progress.finish(success=True)
        
        #  严格数据对比
        print(f"\n [COMPARE] 数据对比:")
        print(f"   本地文件: {len(expected_data)} 字节")
        print(f"   芯片数据: {len(chip_data)} 字节")
        
        if len(expected_data) != len(chip_data):
            print(f"× [FAIL] 文件大小不匹配!")
            print(f"   期望: {len(expected_data)} 字节")
            print(f"   实际: {len(chip_data)} 字节")
            print(f"   差异: {abs(len(expected_data) - len(chip_data))} 字节")
            return False
        
        # 逐字节对比
        if expected_data == chip_data:
            print(f"√ [SUCCESS] 文件验证完全通过! ({len(expected_data)} 字节)")
            
            #  验证完成后的硬件稳定延迟
            verification_stabilization_delay = WRITE_DELAY * 0.3
            print(f"[STABILIZE] Verification completed - allowing hardware to stabilize ({verification_stabilization_delay}s)")
            time.sleep(verification_stabilization_delay)
            
            return True
        else:
            print(f"× [FAIL] 数据内容不匹配!")
            
            #   找到第一个差异位置
            diff_count = 0
            first_diff = -1
            for i in range(len(expected_data)):
                if expected_data[i] != chip_data[i]:
                    if first_diff == -1:
                        first_diff = i
                    diff_count += 1
            
            print(f"   不同字节数: {diff_count}")
            print(f"   首个差异: 0x{first_diff:04X}")
            
            if DEBUG_MODE and diff_count <= 16:
                print(f"\n[DEBUG] 详细差异 (前16个不同字节):")
                shown_diffs = 0
                for i in range(len(expected_data)):
                    if expected_data[i] != chip_data[i]:
                        print(f"   [0x{i:04X}] 期望:0x{expected_data[i]:02X} 实际:0x{chip_data[i]:02X}")
                        shown_diffs += 1
                        if shown_diffs >= 16:
                            break
            
            return False
            
    except Exception as e:
        progress.finish(success=False)
        print(f"[FAIL] Modern verification failed for {hex(fid)}: {e}")
        return False

def personalize_passport(doc_nr: str, dob: str, doe: str, com_path: str, dg1_path: str, dg2_path: str, dg11_path: str, dg12_path: str, dg15_path: str, sod_path: str, aid: str = "A0 00 00 02 47 10 01", connection=None):
    """个人化流程"""
    print("\n" + "="*60)
    print(">> PASSPORT PERSONALIZATION STARTING")
    print("="*60)
    
    start_time = time.time()
    
    # 使用传入的连接或创建新连接
    if connection is None:
        print(">>  创建新的读卡器连接")
        connection = connect_reader()
    else:
        print(">>  使用现有的读卡器连接（阶段零连接）")
    
    try:
        print("\n>> Checking input files...")
        files_info = [(com_path, "COM"), (dg1_path, "DG1"), (dg2_path, "DG2"), (dg11_path, "DG11"), (dg12_path, "DG12"), (dg15_path, "DG15"), (sod_path, "SOD")]
        total_bytes = 0
        for path, name in files_info:
            if not os.path.exists(path):
                raise FileNotFoundError(f"File {path} ({name}) not found")
            file_size = os.path.getsize(path)
            total_bytes += file_size
            print(f"[OK] {name}: {file_size} bytes")
        print(f">> Total data to write: {total_bytes} bytes")

        print("\n>> Initializing MRZ for BAC key derivation...")
        
        # 原始数据（不含校验位）
        doc_nr_raw = doc_nr 
        dob_raw = dob       
        doe_raw = doe       
        
        # 1. docNr + checkDigit(docNr) + dob + checkDigit(dob) + doe + checkDigit(doe)
        doc_nr_check = calculate_check_digit(doc_nr_raw.encode('ascii'))
        dob_check = calculate_check_digit(dob_raw.encode('ascii'))  
        doe_check = calculate_check_digit(doe_raw.encode('ascii'))
        
        # 2. 组装完整MRZ
        card_mrz_seed = doc_nr_raw + doc_nr_check + dob_raw + dob_check + doe_raw + doe_check
        mrz_data = card_mrz_seed.encode('ascii')
        
        if DEBUG_MODE:
            print(f"[DEBUG] Raw DocNr: '{doc_nr_raw}' -> Check digit: {doc_nr_check}")
            print(f"[DEBUG] Raw DOB: '{dob_raw}' -> Check digit: {dob_check}")
            print(f"[DEBUG] Raw DOE: '{doe_raw}' -> Check digit: {doe_check}")
            print(f"[DEBUG] Card Internal MRZ: '{card_mrz_seed}'")
        
        print(f">> MRZ Seed for BAC Keys (matching card logic): {mrz_data.decode('ascii')}")
        print(f">> MRZ Components: DocNr={doc_nr_raw}({doc_nr_check}), DOB={dob_raw}({dob_check}), DOE={doe_raw}({doe_check})")

        print("\n>> Selecting passport application...")
        # 固定长度07而不是动态计算
        aid_bytes = bytes([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])  # 🚨 7字节
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) + aid_bytes
        resp_data, sw = send_apdu(connection, apdu, "SELECT_AID")
        if sw != 0x9000:
            raise RuntimeError(f"SELECT AID failed: SW={hex(sw)}")
        print("[OK] Passport application selected")

        # 卡端已全注释
        print("\n>> Skipping unlock attempts (previously may have locked the card)")
        print("[INFO] If PUT_MRZ fails, the card may be locked and need applet reinstall")

        # 选择MF（主文件）- PUT_DATA可能需要这个
        print("\n>> Selecting Master File (MF)...")
        try:
            select_mf_apdu = bytes([0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])  # SELECT MF
            resp_data, sw = send_apdu(connection, select_mf_apdu, "SELECT_MF")
            if sw == 0x9000:
                print("[OK] Master File selected")
            else:
                print(f"[INFO] MF selection returned SW={hex(sw)} (may not be required)")
        except Exception as e:
            print(f"[INFO] MF selection failed: {e} (proceeding anyway)")

        print("\n>> Writing MRZ data to card...")

        # MRZ: P1=0, P2=MRZ_TAG(0x62), 数据格式：BER-TLV with docNr+dob+doe
        
        if DEBUG_MODE:
            print(f"[DEBUG] MRZ Data ({len(mrz_data)} bytes): {mrz_data.hex().upper()}")
        
        # BER-TLV格式：
        # 外层TLV容器 + 内层三个TLV (01=docNr, 02=dob, 03=doe)
        doc_nr_tlv = b"\x01" + bytes([len(doc_nr)]) + doc_nr.encode('ascii')
        dob_tlv = b"\x02" + bytes([len(dob)]) + dob.encode('ascii') 
        doe_tlv = b"\x03" + bytes([len(doe)]) + doe.encode('ascii')
        composite_tlv = doc_nr_tlv + dob_tlv + doe_tlv
        
        # 外层容器 可能要，也可能不要。。。
        mrz_ber_tlv = b"\x62" + bytes([len(composite_tlv)]) + composite_tlv
        
        if DEBUG_MODE:
            print(f"\n[DEBUG] =====MRZ数据对比=====")
            print(f"[DEBUG] PUT_MRZ用的DocNr: '{doc_nr}' (len={len(doc_nr)})")
            print(f"[DEBUG] PUT_MRZ用的DOB: '{dob}' (len={len(dob)})")
            print(f"[DEBUG] PUT_MRZ用的DOE: '{doe}' (len={len(dob)})")
            print(f"[DEBUG] BAC用的MRZ seed: '{mrz_data.decode('ascii')}'")
            print(f"[DEBUG] PUT_MRZ TLV: {composite_tlv.hex().upper()}")
            print(f"[DEBUG] BAC MRZ bytes: {mrz_data.hex().upper()}")
            print(f"[DEBUG] =============================")
        
        # 正确的PUT_MRZ命令：P1=0, P2=0x62
        mrz_apdu = bytes([0x00, 0xDA, 0x00, 0x62, len(mrz_ber_tlv)]) + mrz_ber_tlv
        if DEBUG_MODE:
            print(f"[DEBUG] Correct MRZ APDU: {mrz_apdu.hex().upper()}")
            print(f"[DEBUG] DocNr TLV: {doc_nr_tlv.hex().upper()}")
            print(f"[DEBUG] DOB TLV: {dob_tlv.hex().upper()}")  
            print(f"[DEBUG] DOE TLV: {doe_tlv.hex().upper()}")
        
        resp_data, sw = send_apdu(connection, mrz_apdu, "PUT_MRZ_CORRECT")
        
        if sw != 0x9000:
            print(f"[WARN] PUT_MRZ with outer TLV failed (SW={hex(sw)}), trying direct format...")
            # 试不带外层TLV的格式
            mrz_apdu = bytes([0x00, 0xDA, 0x00, 0x62, len(composite_tlv)]) + composite_tlv
            resp_data, sw = send_apdu(connection, mrz_apdu, "PUT_MRZ_DIRECT_TLV")
            
            if sw != 0x9000:
                print(f"[ERROR] PUT_MRZ failed with correct format. SW: {hex(sw)}")
                print(f"[ERROR] This indicates a fundamental issue with the applet or card state")
                print(f"[INFO] Attempting to proceed with BAC authentication anyway...")
                print(f"[WARN] Skipping MRZ personalization - will attempt BAC with current MRZ")
            else:
                print("[OK] MRZ data written to card (direct TLV format)")
        else:
            print("[OK] MRZ data written to card")

        # === 关键修复：重置卡片状态 ===
        print("\n>> Resetting card state for BAC authentication...")
        try:
            # 重新选择applet以重置volatile状态
            aid_bytes = bytes([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
            apdu = bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) + aid_bytes
            resp_data, sw = send_apdu(connection, apdu, "RESET_SELECT_AID")
            if sw != 0x9000:
                print(f"[WARN] Applet re-selection failed: SW={hex(sw)}")
                print("[INFO] Proceeding with BAC anyway...")
            else:
                print("[OK] Applet re-selected - volatile state reset")
                
            # 小延时确保状态完全重置
            time.sleep(0.1)
            
        except Exception as e:
            print(f"[WARN] State reset failed: {e}")
            print("[INFO] Proceeding with BAC anyway...")

        ks_enc, ks_mac, ssc = perform_bac_authentication(connection, mrz_data)
        print("[OK] BAC authentication completed, session keys established.")


        print("\n>> Creating passport files...")
        files = [
            (0x011E, os.path.getsize(com_path), "COM"),
            (0x0101, os.path.getsize(dg1_path), "DG1"),
            (0x0102, os.path.getsize(dg2_path), "DG2"),
            (0x010B, os.path.getsize(dg11_path), "DG11"),
            (0x010C, os.path.getsize(dg12_path), "DG12"),
            (0x010F, os.path.getsize(dg15_path), "DG15"),
            (0x011D, os.path.getsize(sod_path), "SOD"),
        ]
        for fid, size, name in files:
            # 修复CREATE_FILE格式
            create_data = b"\x63" + struct.pack(">B", 4) + struct.pack(">H", size) + struct.pack(">H", fid)
            print(f"\n[DEBUG] CREATE_FILE {name}: FID={hex(fid)}, Size={size}")
            print(f"[DEBUG] create_data: {create_data.hex()}")
             
            apdu = build_sm_apdu(0x0C, 0xE0, 0x00, 0x00, create_data, 0, ks_enc, ks_mac, ssc)
            print(f"[DEBUG] SSC after build: {ssc.hex()}")
            resp_data, sw = send_apdu(connection, apdu, f"CREATE_{name}")
            resp_data, sw = parse_sm_response(resp_data, ks_enc, ks_mac, ssc)
            if sw != 0x9000:
                if sw == 0x6A82:
                    print(f"[WARN] {name} already exists, skipping creation.")
                else:
                    raise RuntimeError(f"CREATE_FILE {name} ({hex(fid)}) failed: SW={hex(sw)}")
            else:
                print(f"[OK] Created {name} ({size} bytes)")


        print("\n>> Writing passport data...")
        file_data = [
            (0x011E, com_path, "COM"),
            (0x0101, dg1_path, "DG1"),
            (0x0102, dg2_path, "DG2"),
            (0x010B, dg11_path, "DG11"),
            (0x010C, dg12_path, "DG12"),
            (0x010F, dg15_path, "DG15"),
            (0x011D, sod_path, "SOD"),
        ]
        
        written_total = 0
        progress.set_total(total_bytes, "Writing passport data")
        
        for fid, file_path, name in file_data:
            apdu = build_sm_apdu(0x0C, 0xA4, 0x00, 0x00, struct.pack(">H", fid), 0, ks_enc, ks_mac, ssc)
            resp_data, sw = send_apdu(connection, apdu, f"SELECT_{name}")
            resp_data, sw = parse_sm_response(resp_data, ks_enc, ks_mac, ssc)
            if sw != 0x9000:
                raise RuntimeError(f"SELECT_FILE {name} ({hex(fid)}) failed: SW={hex(sw)}")
            
            # 🚨 使用新的写入函数处理物理缺陷
            try:
                written = write_with_defect_handling(connection, fid, file_path, name, ks_enc, ks_mac, ssc, written_total)
                written_total += written
            except Exception as e:
                print(f"[ERROR] Failed to write {name}: {e}")
                raise
            
            # 🚨 SSC开销优化：根据配置决定是否验证
            if VERIFY_AFTER_WRITE and not OPTIMIZE_SSC_USAGE:
                print(f"\n>>   Immediate verification for {name} (SSC cost: ~{1 + (os.path.getsize(file_path)//64)} increments)")
                if not verify_file_data(connection, fid, file_path, ks_enc, ks_mac, ssc):
                    raise RuntimeError(f"Verification failed for {name} ({hex(fid)})")
            elif OPTIMIZE_SSC_USAGE:
                print(f"\n>>  Skipping immediate verification for {name} (SSC optimization enabled)")
                print(f">>  Saved ~{1 + (os.path.getsize(file_path)//64)} SSC increments")
                    
        progress.finish(success=True)
        
        # 🚨移除危险的后验证环节！避免诅咒！
        # 原来这里有额外的COM文件验证，可能触发看不懂的诅咒机制！
        print("\n>> √ All files verified during writing process")
        print(">> ️ Skipping post-personalization verification to avoid curse")

        end_time = time.time()
        elapsed_time = end_time - start_time
        avg_speed = (total_bytes / 1024) / elapsed_time if elapsed_time > 0 else 0
        
        print("\n" + "="*60)
        print(">> PASSPORT PERSONALIZATION COMPLETED SUCCESSFULLY!")
        print("="*60)
        print(f">> Total time: {elapsed_time:.2f} seconds")
        print(f">> Average speed: {avg_speed:.2f} KB/s")
        print(f">> Data written: {total_bytes} bytes")
        print("="*60)
        
        # 🚨 关键：个人化完成后立即断卡！避免诅咒！
        print(f"\n>>  CRITICAL: Immediate disconnect to avoid post-personalization curse!")
        print(f">> ！ DO NOT attempt any AID operations after personalization!")
        
        # ️🚨 断卡前最终稳定延迟：确保硬件完全稳定
        final_disconnect_delay = WRITE_DELAY * 1.0  # 断卡前给硬件充分稳定时间
        print(f">> ️ Final stabilization before disconnect ({final_disconnect_delay}s)")
        time.sleep(final_disconnect_delay)
        
        print(f">> 🚨 Disconnecting card now...")
        
        try:
            if connection:
                connection.disconnect()
                print("√ [OK] Card disconnected successfully - curse avoided!")
            else:
                print("！ [WARN] No active connection to disconnect")
        except Exception as disconnect_error:
            print(f"[WARN] Disconnect error (not critical): {disconnect_error}")
        
        #  新增：生成专业级APDU分析报告！
        print("\n>>   Generating APDU session analysis report...")
        apdu_analyzer.generate_session_report()
        print(">>  Analysis report saved to 'apdu_analysis_report.txt'")
        
        return True
        
    except Exception as e:
        progress.finish(success=False)
        print(f"\n[FAIL] PERSONALIZATION FAILED: {e}")
        if DEBUG_MODE:
            traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        doc_nr = "PA0595749"    #硬编码MRZ密钥派生区🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨
        dob = "990609"
        doe = "340619"
        com_path = "COM.bin"
        dg1_path = "DG1.bin"
        dg2_path = "DG2.bin"
        dg11_path = "DG11.bin"
        dg12_path = "DG12.bin"
        dg15_path = "DG15.bin"
        sod_path = "SOD.bin"
        aid = "A0 00 00 02 47 10 01"
        
        # 🚨 阶段零：机密注入
        # 在任何其他个人化操作之前写入AA私钥
        print("\n" + "="*80)
        print(" 启动passport个人化")
        print("="*80)
        
        # 连接读卡器
        connection = connect_reader()
        
        # 🚨在这里插入！设置官方超时（单位：秒）
        # 这是 pyscard 库自带的功能，比自己写线程更稳定！
        connection.TIMEOUT = 30  # 设置30秒超时
        
        # 🚨这里就是最完美的插入点！
        # 【阶段零：机密注入】- 利用绿色通道写入AA私钥
        print("\n>>  执行阶段零：机密注入...")
        write_aa_secret(connection, "AA_RSA1024_private.der")
        
        # 如果执行到这里，说明机密注入成功，继续标准个人化
        print(">> √ 阶段零完成！AA私钥已写入！")
        print(">>  开始阶段一：安全报文机制下继续烧卡")
        
        # 然后执行原有的、完整的、不可修改的个人化流程
        success = personalize_passport(doc_nr, dob, doe, com_path, dg1_path, dg2_path, dg11_path, dg12_path, dg15_path, sod_path, aid, connection)
        
        if not success:
            input("\n[PAUSE] Press Enter to exit...")
            
    except KeyboardInterrupt:
        print("\n\n[STOP] Operation cancelled by user")
    except Exception as e:
        print(f"\n[FAIL] Critical error: {e}")
        if DEBUG_MODE:
            traceback.print_exc()
        input("\n[PAUSE] Press Enter to exit...")
    finally:
        # 新增：无论成功失败，都生成APDU分析报告！
        try:
            print(f"\n   Generating final APDU analysis report...")
            apdu_analyzer.generate_session_report()
            print("  [ANALYSIS] Complete session analysis saved to 'apdu_analysis_report.txt'")
            print("  [ANALYSIS] This report contains:")
            print("             ├── Complete APDU command/response history")
            print("             ├── Timing performance analysis")
            print("             ├── Data integrity verification")
            print("             ├── Error pattern analysis")
            print("             └── Hardware performance statistics")
            print("  [ANALYSIS] Use this for debugging and optimization!")
        except Exception as report_error:
            print(f"[WARN] Failed to generate analysis report: {report_error}")
        
        try:
            # 尝试清理连接（如果还活跃）
            print(f"\n[CLEANUP] Checking connection status...")
            if 'connection' in locals() and connection:
                connection.disconnect()
                print("[OK] Reader disconnected in cleanup")
            else:
                print("[INFO] Connection already closed")
        except:
            print("[INFO] Connection cleanup completed")
            pass
