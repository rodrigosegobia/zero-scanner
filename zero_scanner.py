#!/usr/bin/env python3
"""
ZERO Scanner - Advanced SMB Security Assessment Tool
Author: Rodrigo Segobia
Version: 1.0
License: MIT
GitHub: https://github.com/rodrigosegobia/zero-scanner
"""

import os
import sys
import json
import socket
import argparse
import subprocess
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed




class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"
    GRAY = "\033[90m"




def show_zero_art():
    """Display ZERO ASCII art"""
    zero_art = f"""{Colors.CYAN}{Colors.BOLD}
███████╗███████╗██████╗  ██████╗ 
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
  ███╔╝ █████╗  ██████╔╝██║   ██║
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████╗███████╗██║  ██║╚██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
{Colors.END}"""
    print(zero_art)

def show_banner():
    """Display scanner banner"""
    clear_screen()
    show_zero_art()
    banner = f"""{Colors.PURPLE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                    ZERO SCANNER v1.0                         ║
║          Advanced SMB Security Assessment Tool               ║
║                 Author: .Zer0 | github.com/zeroaualy         ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')




def check_all_dependencies():
    """Check ALL required and optional dependencies before execution"""
    print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
    print(f"{Colors.BOLD}        🔧 CHECKING DEPENDENCIES{Colors.END}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.END}")
    

    required_core = [
        ('nmap', 'Network scanning and service detection'),
        ('smbclient', 'SMB protocol client'),
        ('nc', 'Network connectivity testing (netcat)')
    ]
    

    required_enum = [
        ('nmblookup', 'NetBIOS name lookup (Samba)'),
        ('rpcclient', 'RPC client for Windows services'),
        ('net', 'Samba net utility')
    ]
    

    optional_tools = [
        ('enum4linux', 'Windows/Samba enumeration'),
        ('ldapsearch', 'LDAP query tool'),
        ('polenum', 'Windows policy enumeration'),
        ('hydra', 'Brute force tool')
    ]
    
    missing_required = []
    missing_optional = []
    available_required = []
    available_optional = []
    

    print(f"\n{Colors.BOLD}🔧 Core Scanning Tools:{Colors.END}")
    for tool, description in required_core:
        try:
            if tool == 'nc':
                subprocess.run(['which', 'nc'], check=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(['which', tool], check=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  {Colors.GREEN}✓{Colors.END} {tool}: {description}")
            available_required.append(tool)
        except:
            print(f"  {Colors.RED}✗{Colors.END} {tool}: {description} - {Colors.RED}MISSING{Colors.END}")
            missing_required.append(tool)
    

    print(f"\n{Colors.BOLD}🔍 Enumeration Tools:{Colors.END}")
    for tool, description in required_enum:
        try:
            subprocess.run(['which', tool], check=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  {Colors.GREEN}✓{Colors.END} {tool}: {description}")
            available_required.append(tool)
        except:
            print(f"  {Colors.YELLOW}⚠{Colors.END} {tool}: {description} - {Colors.YELLOW}RECOMMENDED{Colors.END}")
            missing_required.append(tool)
    

    print(f"\n{Colors.BOLD}✨ Optional Tools:{Colors.END}")
    for tool, description in optional_tools:
        try:
            subprocess.run(['which', tool], check=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  {Colors.GREEN}✓{Colors.END} {tool}: {description}")
            available_optional.append(tool)
        except:
            print(f"  {Colors.GRAY}○{Colors.END} {tool}: {description} - {Colors.GRAY}OPTIONAL{Colors.END}")
            missing_optional.append(tool)
    

    print(f"\n{Colors.BOLD}📊 Summary:{Colors.END}")
    print(f"  {Colors.GREEN}Available: {len(available_required) + len(available_optional)} tools{Colors.END}")
    
    if missing_required:
        print(f"  {Colors.RED}Missing: {len(missing_required)} required/recommended tools{Colors.END}")
    
    if missing_optional:
        print(f"  {Colors.YELLOW}Optional: {len(missing_optional)} tools not installed{Colors.END}")
    

    if missing_required:
        print(f"\n{Colors.BOLD}🚀 Installation Commands:{Colors.END}")
        

        try:
            with open('/etc/os-release', 'r') as f:
                os_release = f.read().lower()
                
            if 'ubuntu' in os_release or 'debian' in os_release or 'kali' in os_release:
                print(f"{Colors.YELLOW}For Debian/Ubuntu/Kali:{Colors.END}")
                print(f"  sudo apt-get update")
                print(f"  sudo apt-get install -y nmap smbclient netcat samba-common-bin samba-client ldap-utils")
                
            elif 'centos' in os_release or 'rhel' in os_release or 'fedora' in os_release:
                print(f"{Colors.YELLOW}For RHEL/CentOS/Fedora:{Colors.END}")
                print(f"  sudo yum install -y nmap samba-client nc samba-common-tools openldap-clients")
                
            elif 'arch' in os_release:
                print(f"{Colors.YELLOW}For Arch Linux:{Colors.END}")
                print(f"  sudo pacman -S nmap samba nmap netcat ldap-utils")
                
            else:
                print(f"{Colors.YELLOW}General installation:{Colors.END}")
                print(f"  Install: nmap, smbclient, netcat, samba-common-bin, ldap-utils")
                
        except:
            print(f"{Colors.YELLOW}General installation:{Colors.END}")
            print(f"  Install: nmap, smbclient, netcat, samba-common-bin, ldap-utils")
    

    if missing_required:
        print(f"\n{Colors.RED}⚠️  Some required tools are missing!{Colors.END}")
        print(f"{Colors.YELLOW}Basic scanning will work, but advanced features may fail.{Colors.END}")
        
        choice = input(f"\n{Colors.BOLD}Continue anyway? (y/n): {Colors.END}").strip().lower()
        if choice != 'y':
            print(f"{Colors.YELLOW}Please install the missing tools and try again.{Colors.END}")
            return False
    
    return True




class MenuSystem:
    @staticmethod
    def show_main_menu():
        """Display main menu"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        🎯 ZERO SCANNER MAIN MENU{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        menus = [
            f"{Colors.BOLD}[1]{Colors.END} {Colors.GREEN}Quick SMB Scan{Colors.END}",
            f"{Colors.BOLD}[2]{Colors.END} {Colors.YELLOW}Advanced SMB Audit{Colors.END}",
            f"{Colors.BOLD}[3]{Colors.END} {Colors.BLUE}Custom Configuration{Colors.END}",
            f"{Colors.BOLD}[4]{Colors.END} {Colors.PURPLE}Post-Scan Tools{Colors.END}",
            f"{Colors.BOLD}[5]{Colors.END} {Colors.RED}Exit{Colors.END}"
        ]
        
        for menu in menus:
            print(f"  {menu}")
        
        print(f"\n{Colors.GRAY}{'─'*60}{Colors.END}")
        
        while True:
            try:
                choice = input(f"{Colors.BOLD}Select option (1-5): {Colors.END}").strip()
                if choice in ['1', '2', '3', '4', '5']:
                    return choice
                print(f"{Colors.RED}Invalid choice. Please enter 1-5.{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.END}")
                return '5'

    @staticmethod
    def get_target():
        """Get target IP from user"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        🌐 TARGET SELECTION{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        while True:
            try:
                target = input(f"{Colors.BOLD}Enter target IP/hostname: {Colors.END}").strip()
                
                if not target:
                    print(f"{Colors.RED}Please enter a target.{Colors.END}")
                    continue
                
                if target.lower() == 'localhost' or target == '127.0.0.1':
                    print(f"{Colors.YELLOW}⚠️  Scanning localhost. Make sure you have permission.{Colors.END}")
                    confirm = input(f"{Colors.BOLD}Continue? (y/n): {Colors.END}").strip().lower()
                    if confirm != 'y':
                        continue
                
                print(f"{Colors.GREEN}✓ Target set to: {target}{Colors.END}")
                return target
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.END}")
                return None

    @staticmethod
    def get_scan_mode():
        """Get scan mode from user"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        📡 SCAN MODE SELECTION{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        modes = [
            f"{Colors.BOLD}[1]{Colors.END} {Colors.GREEN}Basic Scan{Colors.END} (Ports 139 & 445)",
            f"{Colors.BOLD}[2]{Colors.END} {Colors.YELLOW}Full Audit{Colors.END} (All SMB/AD ports)",
            f"{Colors.BOLD}[3]{Colors.END} {Colors.BLUE}Custom Ports{Colors.END} (Specify custom ports)"
        ]
        
        for mode in modes:
            print(f"  {mode}")
        
        print()
        
        while True:
            try:
                choice = input(f"{Colors.BOLD}Select scan mode (1-3): {Colors.END}").strip()
                if choice in ['1', '2', '3']:
                    return choice
                print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.END}")
                return None

    @staticmethod
    def get_custom_ports():
        """Get custom ports from user"""
        print(f"\n{Colors.CYAN}Enter ports to scan:{Colors.END}")
        print(f"{Colors.GRAY}Examples: 139,445,135,389{Colors.END}")
        print(f"{Colors.GRAY}          1-100 (range){Colors.END}")
        print(f"{Colors.GRAY}          22,80,443,8080-8090{Colors.END}\n")
        
        while True:
            try:
                ports_input = input(f"{Colors.BOLD}Ports: {Colors.END}").strip()
                
                if not ports_input:
                    print(f"{Colors.RED}Please enter at least one port.{Colors.END}")
                    continue
                
                ports = []
                for part in ports_input.split(','):
                    part = part.strip()
                    if '-' in part:
                        try:
                            start, end = map(int, part.split('-'))
                            ports.extend(range(start, end + 1))
                        except ValueError:
                            print(f"{Colors.RED}Invalid range: {part}{Colors.END}")
                            continue
                    else:
                        try:
                            ports.append(int(part))
                        except ValueError:
                            print(f"{Colors.RED}Invalid port: {part}{Colors.END}")
                            continue
                
                if not ports:
                    print(f"{Colors.RED}No valid ports entered.{Colors.END}")
                    continue
                
                ports = sorted(set(ports))
                
                invalid_ports = [p for p in ports if p < 1 or p > 65535]
                if invalid_ports:
                    print(f"{Colors.RED}Invalid ports (must be 1-65535): {invalid_ports}{Colors.END}")
                    continue
                
                print(f"{Colors.GREEN}✓ Will scan {len(ports)} ports{Colors.END}")
                return ports
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.END}")
                return None

    @staticmethod
    def get_scan_options():
        """Get additional scan options"""
        options = {
            'verbose': False,
            'force': False,
            'save_report': True,
            'output_dir': os.getcwd(),
            'no_banner': False,
            'aggressive': False
        }
        
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        ⚙️ SCAN OPTIONS{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        

        verbose = input(f"{Colors.BOLD}Enable verbose output? (y/n): {Colors.END}").strip().lower()
        options['verbose'] = (verbose == 'y')
        

        force = input(f"{Colors.BOLD}Force scan even if ports appear closed? (y/n): {Colors.END}").strip().lower()
        options['force'] = (force == 'y')
        

        aggressive = input(f"{Colors.BOLD}Enable aggressive mode? (y/n): {Colors.END}").strip().lower()
        options['aggressive'] = (aggressive == 'y')
        

        save_report = input(f"{Colors.BOLD}Save results to file? (y/n): {Colors.END}").strip().lower()
        options['save_report'] = (save_report == 'y')
        
        if options['save_report']:
            output_dir = input(f"{Colors.BOLD}Output directory (Enter for current): {Colors.END}").strip()
            if output_dir and os.path.isdir(output_dir):
                options['output_dir'] = output_dir
        

        hide_banner = input(f"{Colors.BOLD}Hide banner on next run? (y/n): {Colors.END}").strip().lower()
        options['no_banner'] = (hide_banner == 'y')
        
        return options

    @staticmethod
    def configure_tools():
        """Configure tools and wordlists"""
        config = {
            'wordlist_users': None,
            'wordlist_passwords': None,
            'enum4linux_path': 'enum4linux',
            'hydra_path': 'hydra',
            'timeout': 30,
            'threads': 10
        }
        
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        ⚙️ TOOL CONFIGURATION{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        print(f"{Colors.BOLD}Wordlist Configuration:{Colors.END}\n")
        

        use_wordlist = input(f"{Colors.BOLD}Use custom user wordlist? (y/n): {Colors.END}").strip().lower()
        if use_wordlist == 'y':
            while True:
                path = input(f"{Colors.BOLD}Path to user wordlist: {Colors.END}").strip()
                if os.path.exists(path):
                    config['wordlist_users'] = path
                    print(f"{Colors.GREEN}✓ User wordlist set: {path}{Colors.END}")
                    break
                else:
                    print(f"{Colors.RED}✗ File not found: {path}{Colors.END}")
                    retry = input(f"{Colors.BOLD}Try again? (y/n): {Colors.END}").strip().lower()
                    if retry != 'y':
                        break
        

        use_passlist = input(f"{Colors.BOLD}Use custom password wordlist? (y/n): {Colors.END}").strip().lower()
        if use_passlist == 'y':
            while True:
                path = input(f"{Colors.BOLD}Path to password wordlist: {Colors.END}").strip()
                if os.path.exists(path):
                    config['wordlist_passwords'] = path
                    print(f"{Colors.GREEN}✓ Password wordlist set: {path}{Colors.END}")
                    break
                else:
                    print(f"{Colors.RED}✗ File not found: {path}{Colors.END}")
                    retry = input(f"{Colors.BOLD}Try again? (y/n): {Colors.END}").strip().lower()
                    if retry != 'y':
                        break
        

        try:
            timeout = input(f"{Colors.BOLD}Scan timeout (seconds, default 30): {Colors.END}").strip() or "30"
            config['timeout'] = max(10, min(int(timeout), 300))
            print(f"{Colors.GREEN}✓ Timeout set to {config['timeout']} seconds{Colors.END}")
        except ValueError:
            print(f"{Colors.YELLOW}⚠ Using default timeout: 30 seconds{Colors.END}")
        

        try:
            threads = input(f"{Colors.BOLD}Number of threads (default 10): {Colors.END}").strip() or "10"
            config['threads'] = max(1, min(int(threads), 50))
            print(f"{Colors.GREEN}✓ Threads set to {config['threads']}{Colors.END}")
        except ValueError:
            print(f"{Colors.YELLOW}⚠ Using default threads: 10{Colors.END}")
        
        print(f"\n{Colors.GREEN}✓ Configuration saved{Colors.END}")
        return config

    @staticmethod
    def show_next_steps(target, scan_results):
        """Show next steps menu after scan"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        🔄 POST-SCAN TOOLS - {target}{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        steps = [
            f"{Colors.BOLD}[1]{Colors.END} {Colors.GREEN}Detailed Enumeration{Colors.END} (enum4linux)",
            f"{Colors.BOLD}[2]{Colors.END} {Colors.YELLOW}Share Access Testing{Colors.END} (smbclient)",
            f"{Colors.BOLD}[3]{Colors.END} {Colors.BLUE}Brute Force Testing{Colors.END} (hydra)",
            f"{Colors.BOLD}[4]{Colors.END} {Colors.PURPLE}Vulnerability Scanning{Colors.END} (nmap)",
            f"{Colors.BOLD}[5]{Colors.END} {Colors.WHITE}Generate Commands{Colors.END} (manual testing)",
            f"{Colors.BOLD}[6]{Colors.END} {Colors.RED}Return to Main Menu{Colors.END}"
        ]
        
        for step in steps:
            print(f"  {step}")
        
        print()
        
        while True:
            try:
                choice = input(f"{Colors.BOLD}Select option (1-6): {Colors.END}").strip()
                if choice in ['1', '2', '3', '4', '5', '6']:
                    return choice
                print(f"{Colors.RED}Invalid choice. Please enter 1-6.{Colors.END}")
            except KeyboardInterrupt:
                return '6'




class PortChecker:
    @staticmethod
    def check_port_socket(target, port, protocol="tcp", timeout=2):
        """Check port using socket"""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(timeout)
            
            if protocol == "tcp":
                result = sock.connect_ex((target, port))
                sock.close()
                return result == 0
            else:
                sock.sendto(b'\x00', (target, port))
                sock.settimeout(1)
                sock.recvfrom(1024)
                sock.close()
                return True
        except socket.timeout:
            if protocol == "udp":
                return "filtered"
            return False
        except ConnectionRefusedError:
            return False
        except Exception:
            return False

    @staticmethod
    def check_port_netcat(target, port, protocol="tcp", timeout=2):
        """Check port using netcat"""
        try:
            if protocol == "tcp":
                cmd = f"timeout {timeout} nc -zv -w1 {target} {port} 2>&1"
            else:
                cmd = f"timeout {timeout} nc -zu -w1 {target} {port} 2>&1"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return "succeeded" in result.stdout or "open" in result.stdout
        except:
            return False




class ZeroScanner:
    def __init__(self, target, output=None, verbose=False, force=False, scan_mode="basic", custom_ports=None):
        self.target = target
        self.output_file = output
        self.verbose = verbose
        self.force = force
        self.scan_mode = scan_mode
        self.custom_ports = custom_ports
        self.scan_results = {
            'ports': [],
            'shares': [],
            'os_info': 'Unknown',
            'eternalblue': False,
            'start_time': datetime.now().isoformat()
        }
        self.port_checker = PortChecker()
    
    def log(self, message, level="INFO"):
        """Log messages with colors"""
        level_colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "SCAN": Colors.PURPLE,
            "DEBUG": Colors.GRAY
        }
        
        color = level_colors.get(level, Colors.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        log_msg = f"{Colors.GRAY}[{timestamp}]{Colors.END} {color}[{level}]{Colors.END} {message}"
        print(log_msg)
        
        if self.output_file and level in ["SUCCESS", "WARNING", "ERROR", "SCAN"]:
            with open(self.output_file, 'a') as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
    
    def check_dependencies(self):
        """Check for required tools"""
        tools = ['nmap', 'smbclient', 'nc']
        missing = []
        
        for tool in tools:
            try:
                if tool == 'nc':
                    subprocess.run(['which', 'nc'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                else:
                    subprocess.run([tool, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                self.log(f"{tool} found", "SUCCESS")
            except:
                missing.append(tool)
                self.log(f"{tool} not found", "WARNING")
        
        if missing:
            self.log(f"Missing tools: {', '.join(missing)}", "ERROR")
        
        return len(missing) == 0
    
    def get_ports_to_scan(self):
        """Get ports based on scan mode"""
        SMB_PORTS = {
            "basic": [
                {"port": 139, "protocol": "tcp", "service": "NetBIOS Session"},
                {"port": 445, "protocol": "tcp", "service": "SMB over TCP"}
            ],
            "full": [
                {"port": 139, "protocol": "tcp", "service": "NetBIOS Session"},
                {"port": 445, "protocol": "tcp", "service": "SMB over TCP"},
                {"port": 137, "protocol": "udp", "service": "NetBIOS Name Service"},
                {"port": 138, "protocol": "udp", "service": "NetBIOS Datagram"},
                {"port": 135, "protocol": "tcp", "service": "MSRPC"},
                {"port": 389, "protocol": "tcp", "service": "LDAP"},
                {"port": 636, "protocol": "tcp", "service": "LDAPS"},
                {"port": 88, "protocol": "tcp", "service": "Kerberos"},
                {"port": 464, "protocol": "tcp", "service": "Kerberos Password"},
                {"port": 53, "protocol": "tcp", "service": "DNS"},
                {"port": 53, "protocol": "udp", "service": "DNS"},
                {"port": 3389, "protocol": "tcp", "service": "RDP"}
            ]
        }
        
        if self.scan_mode == "custom" and self.custom_ports:
            return [{"port": p, "protocol": "tcp", "service": "Custom"} for p in self.custom_ports]
        elif self.scan_mode in SMB_PORTS:
            return SMB_PORTS[self.scan_mode]
        else:
            return SMB_PORTS["basic"]
    
    def scan_ports(self):
        """Scan SMB ports"""
        ports_to_scan = self.get_ports_to_scan()
        
        if self.scan_mode == "custom":
            self.log(f"Starting custom port scan ({len(ports_to_scan)} ports)", "SCAN")
        else:
            self.log(f"Starting {self.scan_mode} scan ({len(ports_to_scan)} ports)", "SCAN")
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {}
            
            for port_info in ports_to_scan:
                future = executor.submit(
                    self.check_single_port,
                    port_info['port'],
                    port_info.get('protocol', 'tcp'),
                    port_info.get('service', 'Unknown')
                )
                future_to_port[future] = port_info
            
            for future in as_completed(future_to_port):
                port_info = future_to_port[future]
                try:
                    is_open, _ = future.result()
                    
                    if is_open:
                        status = "OPEN"
                        color = Colors.GREEN
                        protocol = port_info.get('protocol', 'tcp')
                        service = port_info.get('service', 'Unknown')
                        self.log(f"Port {port_info['port']}/{protocol} ({service}): {color}{status}{Colors.END}", "SUCCESS")
                        open_ports.append({
                            'port': port_info['port'],
                            'protocol': protocol,
                            'service': service,
                            'status': status
                        })
                    elif self.verbose:
                        protocol = port_info.get('protocol', 'tcp')
                        self.log(f"Port {port_info['port']}/{protocol}: CLOSED", "DEBUG")
                except Exception as e:
                    self.log(f"Error scanning port {port_info['port']}: {e}", "ERROR")
        
        self.scan_results['ports'] = open_ports
        self.scan_results['total_scanned'] = len(ports_to_scan)
        self.scan_results['open_ports'] = len(open_ports)
        
        self.log(f"\n📊 Port Scan Summary:", "INFO")
        self.log(f"  Scanned: {len(ports_to_scan)} ports", "INFO")
        self.log(f"  Open: {len(open_ports)} ports", "SUCCESS" if open_ports else "WARNING")
        
        return len(open_ports) > 0 or self.force
    
    def check_single_port(self, port, protocol="tcp", service="Unknown"):
        """Check a single port"""
        methods = {}
        methods['socket'] = self.port_checker.check_port_socket(self.target, port, protocol)
        methods['netcat'] = self.port_checker.check_port_netcat(self.target, port, protocol)
        
        is_open = any(methods.values())
        if protocol == "udp" and methods.get('socket') == "filtered":
            is_open = "filtered"
        
        return is_open, methods
    
    def run_nmap_smb_scan(self):
        """Run detailed Nmap SMB scan"""
        self.log("\nRunning detailed SMB scan with Nmap...", "SCAN")
        
        try:
            cmd = f"nmap -p 139,445 -sV --script smb-os-discovery,smb-security-mode,smb-protocols {self.target}"
            
            if self.verbose:
                self.log(f"Command: {cmd}", "DEBUG")
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                self.log("Nmap scan completed", "SUCCESS")
                
                for line in result.stdout.split('\n'):
                    if "OS:" in line:
                        self.scan_results['os_info'] = line.strip()
                        self.log(f"OS Info: {line.strip()}", "SUCCESS")
                        break
                    elif "Samba" in line or "Windows" in line:
                        self.scan_results['os_info'] = line.strip()
                        self.log(f"Service: {line.strip()}", "SUCCESS")
                        break
                
                if self.verbose:
                    print(result.stdout[:800])
                
            else:
                self.log("Nmap scan failed", "ERROR")
                
        except Exception as e:
            self.log(f"Nmap error: {e}", "ERROR")
    
    def enumerate_shares(self):
        """Enumerate SMB shares"""
        self.log("\nEnumerating SMB shares...", "SCAN")
        
        try:
            cmd = f"smbclient -L //{self.target}/ -N 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            shares = []
            lines = result.stdout.split('\n')
            in_share_section = False
            
            for line in lines:
                line = line.strip()
                
                if "Sharename" in line and "Type" in line and "Comment" in line:
                    in_share_section = True
                    continue
                
                if in_share_section:
                    if line.startswith('---') or not line:
                        continue
                    
                    if "Server" in line or "Workgroup" in line or "Reconnecting" in line:
                        break
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_type = parts[1]
                        comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                        
                        if share_type in ['Disk', 'IPC', 'Printer']:
                            shares.append({
                                'name': share_name,
                                'type': share_type,
                                'comment': comment
                            })
                            
                            self.log(f"Found share: {share_name} ({share_type})", "SUCCESS")
            
            self.scan_results['shares'] = shares
            self.scan_results['shares_count'] = len(shares)
            
            if not shares:
                self.log("No accessible shares found", "WARNING")
            else:
                self.log(f"Total shares found: {len(shares)}", "SUCCESS")
                
        except Exception as e:
            self.log(f"Share enumeration error: {e}", "ERROR")
    
    def check_eternalblue(self):
        """Check for MS17-010 EternalBlue vulnerability"""
        self.log("\nChecking for EternalBlue (MS17-010)...", "SCAN")
        
        try:
            cmd = f"nmap -p 445 --script smb-vuln-ms17-010 {self.target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if "VULNERABLE" in result.stdout:
                self.log("🚨 VULNERABLE to EternalBlue (MS17-010)!", "ERROR")
                self.scan_results['eternalblue'] = True
            else:
                self.log("Not vulnerable to EternalBlue", "SUCCESS")
                self.scan_results['eternalblue'] = False
                
        except Exception as e:
            self.log(f"EternalBlue check error: {e}", "ERROR")
    
    def generate_report(self, output_dir="."):
        """Generate scan report"""
        self.log("\nGenerating final report...", "INFO")
        
        report = {
            'scanner': 'ZERO Scanner v1.0',
            'author': '.Zer0',
            'github': 'https://github.com/zeroaualy/zero-scanner',
            'target': self.target,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_mode': self.scan_mode,
            'scan_results': self.scan_results
        }
        

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = os.path.join(output_dir, f"zero_scan_{self.target}_{timestamp}.json")
        
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        self.log(f"JSON report saved to: {json_file}", "SUCCESS")
        

        text_file = os.path.join(output_dir, f"zero_scan_{self.target}_{timestamp}.txt")
        
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write(f"ZERO SCANNER REPORT\n")
            f.write(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Mode: {self.scan_mode}\n")
            f.write("="*70 + "\n\n")
            
            f.write("[SUMMARY]\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Ports scanned: {self.scan_results.get('total_scanned', 0)}\n")
            f.write(f"Ports open: {self.scan_results.get('open_ports', 0)}\n")
            f.write(f"Shares found: {self.scan_results.get('shares_count', 0)}\n")
            f.write(f"EternalBlue vulnerable: {self.scan_results.get('eternalblue', False)}\n")
            f.write(f"OS detected: {self.scan_results.get('os_info', 'Unknown')}\n\n")
            
            if self.scan_results.get('ports'):
                f.write("[OPEN PORTS]\n")
                for port in self.scan_results['ports']:
                    f.write(f"  {port['port']}/{port['protocol']} - {port['service']}\n")
                f.write("\n")
            
            if self.scan_results.get('shares'):
                f.write("[SMB SHARES]\n")
                for share in self.scan_results['shares']:
                    f.write(f"  {share['name']} ({share['type']})")
                    if share.get('comment'):
                        f.write(f" - {share['comment']}")
                    f.write("\n")
                f.write("\n")
            
            f.write("[RECOMMENDATIONS]\n")
            rec_num = 1
            
            if self.scan_results.get('eternalblue') == True:
                f.write(f"{rec_num}. CRITICAL: Patch MS17-010 vulnerability immediately!\n")
                rec_num += 1
            
            if self.scan_results.get('shares_count', 0) > 0:
                f.write(f"{rec_num}. Review SMB share permissions\n")
                rec_num += 1
            
            if self.scan_results.get('ports_open', 0) > 0:
                f.write(f"{rec_num}. Enable SMB signing for security\n")
                rec_num += 1
                f.write(f"{rec_num}. Use strong passwords for SMB access\n")
            
            if rec_num == 1:
                f.write("1. No critical issues found\n")
        
        self.log(f"Text report saved to: {text_file}", "SUCCESS")
        return report
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}           SCAN COMPLETED - SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
        
        print(f"{Colors.BOLD}📊 RESULTS:{Colors.END}")
        print(f"  • Target: {self.target}")
        print(f"  • Scan Mode: {self.scan_mode.upper()}")
        print(f"  • Ports Open: {self.scan_results.get('open_ports', 0)}/{self.scan_results.get('total_scanned', 0)}")
        print(f"  • Shares Found: {self.scan_results.get('shares_count', 0)}")
        
        eternalblue = self.scan_results.get('eternalblue')
        if eternalblue == True:
            print(f"  • EternalBlue: {Colors.RED}VULNERABLE{Colors.END}")
        else:
            print(f"  • EternalBlue: {Colors.GREEN}NOT VULNERABLE{Colors.END}")
        
        os_info = self.scan_results.get('os_info', 'Unknown')
        if os_info != 'Unknown':
            print(f"  • OS Info: {os_info}")
        
        print(f"\n{Colors.BOLD}🎯 RECOMMENDATIONS:{Colors.END}")
        rec_num = 1
        
        if eternalblue == True:
            print(f"  {rec_num}. {Colors.RED}PATCH MS17-010 vulnerability!{Colors.END}")
            rec_num += 1
        
        if self.scan_results.get('shares_count', 0) > 0:
            print(f"  {rec_num}. Review share permissions")
            rec_num += 1
        
        if self.scan_results.get('ports_open', 0) > 0:
            print(f"  {rec_num}. Enable SMB signing")
            rec_num += 1
            print(f"  {rec_num}. Use strong passwords")
        
        if rec_num == 1:
            print("  1. No critical issues found")
        
        print(f"\n{Colors.GREEN}✓ Reports have been saved{Colors.END}")
    
    def run_scan(self):
        """Execute complete scan"""
        try:
            if not self.check_dependencies():
                if not self.force:
                    self.log("Missing dependencies", "ERROR")
                    return False
            
            if not self.scan_ports():
                if not self.force:
                    self.log("No open ports found", "WARNING")
                    return False
            
            smb_ports_open = any(p['port'] in [139, 445] for p in self.scan_results.get('ports', []))
            
            if smb_ports_open or self.force:
                self.run_nmap_smb_scan()
                self.enumerate_shares()
                self.check_eternalblue()
            
            if self.output_file:
                self.generate_report(os.path.dirname(self.output_file))
            else:
                self.generate_report()
            
            self.print_summary()
            return True
            
        except KeyboardInterrupt:
            self.log("\nScan interrupted", "WARNING")
            return False
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            return False




class PostScanTools:
    @staticmethod
    def run_enum4linux(target, config):
        """Run enum4linux comprehensive scan"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        🔍 ENUM4LINUX - {target}{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        

        missing_deps = []
        for tool in ['nmblookup', 'rpcclient', 'smbclient', 'ldapsearch']:
            try:
                subprocess.run(['which', tool], check=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                missing_deps.append(tool)
        
        if missing_deps:
            print(f"{Colors.RED}Missing dependencies for enum4linux:{Colors.END}")
            for dep in missing_deps:
                print(f"  {Colors.RED}✗{Colors.END} {dep}")
            print(f"\n{Colors.YELLOW}Install with:{Colors.END}")
            print(f"  sudo apt-get install samba-common-bin samba-client ldap-utils")
            return
        
        commands = [
            f"enum4linux -a {target}",
            f"enum4linux -U {target}",
            f"enum4linux -G {target}",
            f"enum4linux -S {target}"
        ]
        
        for cmd in commands:
            print(f"{Colors.BOLD}Running: {cmd}{Colors.END}")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=config.get('timeout', 30))
                print(result.stdout[:500])
                print(f"{Colors.GREEN}{'─'*40}{Colors.END}\n")
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.END}\n")
    
    @staticmethod
    def test_share_access(target, shares):
        """Test access to SMB shares"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        🔓 SHARE ACCESS TESTING - {target}{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        if not shares:
            print(f"{Colors.YELLOW}No shares to test.{Colors.END}")
            return
        
        print(f"{Colors.BOLD}Testing all shares anonymously...{Colors.END}\n")
        
        for share in shares[:5]:
            share_name = share['name']
            cmd = f"smbclient //{target}/{share_name} -N -c 'ls' 2>&1"
            
            print(f"Testing {share_name}...")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                if "NT_STATUS_ACCESS_DENIED" in result.stdout:
                    print(f"  {Colors.RED}✗ Access denied{Colors.END}")
                elif "Domain=" in result.stdout:
                    print(f"  {Colors.GREEN}✓ Access granted!{Colors.END}")
                else:
                    print(f"  {Colors.YELLOW}? {result.stdout[:50]}...{Colors.END}")
            except Exception as e:
                print(f"  {Colors.RED}Error: {e}{Colors.END}")
    
    @staticmethod  
    def run_vulnerability_scan(target):
        """Run SMB vulnerability scans"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        ⚠️ VULNERABILITY SCANNING - {target}{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        vuln_scripts = [
            "smb-vuln-ms17-010",
            "smb-vuln-ms10-054",
            "smb-vuln-ms10-061",
            "smb-vuln-cve-2017-7494"
        ]
        
        for script in vuln_scripts:
            cmd = f"nmap -p 445 --script {script} {target}"
            print(f"{Colors.BOLD}Checking: {script}{Colors.END}")
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if "VULNERABLE" in result.stdout:
                    print(f"{Colors.RED}  🚨 VULNERABILITY FOUND!{Colors.END}")
                else:
                    print(f"{Colors.GREEN}  ✓ Not vulnerable{Colors.END}")
            except Exception:
                print(f"{Colors.YELLOW}  ⚠ Scan failed{Colors.END}")
    
    @staticmethod
    def generate_commands(target, scan_results):
        """Generate commands for manual testing"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}        📋 GENERATED COMMANDS - {target}{Colors.END}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.END}\n")
        
        commands = f"""
{Colors.BOLD}📌 ENUMERATION COMMANDS:{Colors.END}

{Colors.GREEN}1. Detailed Enumeration:{Colors.END}
enum4linux -a {target}
enum4linux -U {target}
enum4linux -G {target}

{Colors.GREEN}2. SMB Share Discovery:{Colors.END}
smbclient -L //{target}/ -N
smbclient -L //{target}/ -U "guest"

{Colors.GREEN}3. Share Access Testing:{Colors.END}
"""
        
        if scan_results.get('shares'):
            for share in scan_results['shares'][:3]:
                share_name = share['name']
                commands += f"smbclient //{target}/{share_name} -N\n"
        
        commands += f"""
{Colors.GREEN}4. Vulnerability Scanning:{Colors.END}
nmap --script smb-vuln-* -p 445,139 {target}
nmap -p 445 --script smb-vuln-ms17-010 {target}

{Colors.GREEN}5. Advanced Detection:{Colors.END}
nmap -sV -sC -p 445,139 {target}
nmap -p 445 --script smb-protocols {target}

{Colors.YELLOW}⚠️ LEGAL DISCLAIMER:{Colors.END}
Only use on systems you own or have permission to test.
"""
        
        print(commands)
        
        save = input(f"\n{Colors.BOLD}Save to file? (y/n): {Colors.END}").strip().lower()
        if save == 'y':
            filename = f"commands_{target}.txt"
            with open(filename, 'w') as f:
                f.write(commands)
            print(f"{Colors.GREEN}Saved to: {filename}{Colors.END}")




class ZeroScannerApp:
    def __init__(self):
        self.config = {}
        self.scan_results = {}
        self.current_target = None
    
    def run(self):
        """Main application loop"""
        while True:
            try:
                show_banner()
                

                if not check_all_dependencies():
                    print(f"\n{Colors.RED}Cannot continue without required dependencies.{Colors.END}")
                    choice = input(f"{Colors.BOLD}Exit? (y/n): {Colors.END}").strip().lower()
                    if choice == 'y':
                        sys.exit(1)
                    else:
                        continue
                
                choice = MenuSystem.show_main_menu()
                
                if choice == '1':
                    self.quick_scan()
                elif choice == '2':
                    self.advanced_audit()
                elif choice == '3':
                    self.custom_configuration()
                elif choice == '4':
                    self.post_scan_tools()
                elif choice == '5':
                    self.exit_app()
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.END}")
                time.sleep(1)
            except Exception as e:
                print(f"\n{Colors.RED}Error: {e}{Colors.END}")
                time.sleep(2)
    
    def quick_scan(self):
        """Run quick SMB scan"""
        clear_screen()
        show_banner()
        
        target = MenuSystem.get_target()
        if not target:
            return
        
        self.current_target = target
        
        print(f"\n{Colors.BOLD}Starting quick scan...{Colors.END}")
        time.sleep(1)
        
        scanner = ZeroScanner(target=target, scan_mode="basic", verbose=False)
        success = scanner.run_scan()
        
        if success:
            self.scan_results = scanner.scan_results
            self.show_next_steps()
    
    def advanced_audit(self):
        """Run advanced audit"""
        clear_screen()
        show_banner()
        
        target = MenuSystem.get_target()
        if not target:
            return
        
        self.current_target = target
        
        mode_choice = MenuSystem.get_scan_mode()
        if not mode_choice:
            return
        
        if mode_choice == '1':
            scan_mode = "basic"
            custom_ports = None
        elif mode_choice == '2':
            scan_mode = "full"
            custom_ports = None
        else:
            custom_ports = MenuSystem.get_custom_ports()
            if not custom_ports:
                return
            scan_mode = "custom"
        
        options = MenuSystem.get_scan_options()
        
        print(f"\n{Colors.BOLD}Starting advanced audit...{Colors.END}")
        time.sleep(1)
        
        scanner = ZeroScanner(
            target=target,
            scan_mode=scan_mode,
            custom_ports=custom_ports,
            verbose=options['verbose'],
            force=options['force']
        )
        
        if options['save_report']:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scanner.output_file = os.path.join(options['output_dir'], f"scan_{target}_{timestamp}.json")
        
        success = scanner.run_scan()
        
        if success:
            self.scan_results = scanner.scan_results
            self.show_next_steps()
    
    def custom_configuration(self):
        """Configure tools"""
        clear_screen()
        show_banner()
        
        self.config = MenuSystem.configure_tools()
        input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.END}")
    
    def post_scan_tools(self):
        """Run post-scan tools"""
        if not self.current_target:
            print(f"\n{Colors.RED}No target scanned yet.{Colors.END}")
            input(f"{Colors.BOLD}Press Enter to continue...{Colors.END}")
            return
        
        clear_screen()
        show_banner()
        
        while True:
            choice = MenuSystem.show_next_steps(self.current_target, self.scan_results)
            
            if choice == '1':
                PostScanTools.run_enum4linux(self.current_target, self.config)
            elif choice == '2':
                shares = self.scan_results.get('shares', [])
                PostScanTools.test_share_access(self.current_target, shares)
            elif choice == '3':
                print(f"\n{Colors.YELLOW}Brute force requires Hydra and wordlists.{Colors.END}")
                print(f"{Colors.YELLOW}Configure in Custom Configuration menu.{Colors.END}")
            elif choice == '4':
                PostScanTools.run_vulnerability_scan(self.current_target)
            elif choice == '5':
                PostScanTools.generate_commands(self.current_target, self.scan_results)
            elif choice == '6':
                break
            
            if choice != '6':
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.END}")
    
    def show_next_steps(self):
        """Show next steps after scan"""
        choice = MenuSystem.show_next_steps(self.current_target, self.scan_results)
        
        if choice == '1':
            PostScanTools.run_enum4linux(self.current_target, self.config)
        elif choice == '2':
            shares = self.scan_results.get('shares', [])
            PostScanTools.test_share_access(self.current_target, shares)
        elif choice == '4':
            PostScanTools.run_vulnerability_scan(self.current_target)
        elif choice == '5':
            PostScanTools.generate_commands(self.current_target, self.scan_results)
        
        if choice != '6':
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.END}")
    
    def exit_app(self):
        """Exit application"""
        print(f"\n{Colors.GREEN}Thank you for using ZERO Scanner!{Colors.END}")
        print(f"{Colors.GRAY}Author: .Zer0 | GitHub: zeroaualy{Colors.END}\n")
        sys.exit(0)




def cli_mode():
    """Command line interface mode"""
    parser = argparse.ArgumentParser(description='ZERO Scanner - Advanced SMB Security Assessment Tool')
    parser.add_argument('target', nargs='?', help='Target IP address or hostname')
    parser.add_argument('-m', '--mode', choices=['basic', 'full', 'custom'], default='basic',
                       help='Scan mode: basic, full, or custom')
    parser.add_argument('-p', '--ports', help='Custom ports (comma-separated or ranges)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-f', '--force', action='store_true', help='Force scan')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    
    args = parser.parse_args()
    

    if not check_all_dependencies():
        print(f"{Colors.RED}Cannot continue without required dependencies.{Colors.END}")
        sys.exit(1)
    
    if args.interactive or not args.target:

        app = ZeroScannerApp()
        app.run()
    else:

        custom_ports = None
        if args.mode == 'custom' and args.ports:
            try:
                ports = []
                for part in args.ports.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(part))
                custom_ports = sorted(set(ports))
            except ValueError:
                print(f"{Colors.RED}Invalid port format{Colors.END}")
                return
        
        scanner = ZeroScanner(
            target=args.target,
            output=args.output,
            verbose=args.verbose,
            force=args.force,
            scan_mode=args.mode,
            custom_ports=custom_ports
        )
        
        scanner.run_scan()




if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            cli_mode()
        else:
            app = ZeroScannerApp()
            app.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scanner terminated{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.END}")
        sys.exit(1)
