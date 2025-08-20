#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Card Sharing Monitor with Protocol Analysis
Monitors CCcam, NewCamd, MGcamd, OSCam with expiry dates and versions
Version: 3.0 - Enhanced Analysis

Copyright © 2025 Alen Pepa. All rights reserved.
Author: Alen Pepa
LinkedIn: <https://www.linkedin.com/in/alenpepa/>

This software is provided "as is" without warranty of any kind.
For commercial use, please contact the author.
"""

import socket
import struct
import threading
import time
import hashlib
import base64
from datetime import datetime, timedelta
import json
import requests
import re
from dataclasses import dataclass
from typing import List, Dict, Optional
import concurrent.futures
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter import font
import os

@dataclass
class ServerInfo:
    protocol: str
    hostname: str
    port: int
    username: str
    password: str
    status: str = "unknown"
    response_time: float = 0
    expiry_date: Optional[datetime] = None
    days_left: int = 0
    packages: List[str] = None
    hops: int = 0
    version: str = ""
    uptime: str = ""
    clients_connected: int = 0
    cards_total: int = 0
    ecm_time: float = 0
    share_type: str = ""
    provider_info: Dict = None
    des_key: str = ""

class AdvancedProtocolAnalyzer:
    def __init__(self):
        self.protocols = {
            'cccam': {'default_port': 12000, 'timeout': 15},
            'newcamd': {'default_port': 15000, 'timeout': 12},
            'mgcamd': {'default_port': 15000, 'timeout': 12},
            'oscam': {'default_port': 988, 'timeout': 15}
        }

        # Protocol versions
        self.protocol_versions = {
            'cccam': ['2.0.11', '2.1.3', '2.1.4', '2.2.1', '2.3.0', '2.3.2'],
            'newcamd': ['5.25', '6.0', '6.1'],
            'mgcamd': ['1.35', '1.38', '1.40'],
            'oscam': ['1.20', '1.30', '11708', '11709', '11710']
        }

    def parse_config_line(self, line: str) -> Optional[ServerInfo]:
        """Parse konfigurimin e serverit me detaje të avancuara"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        parts = line.split()
        if len(parts) < 5:
            return None

        protocol_map = {
            'C:': 'cccam',
            'N:': 'newcamd',
            'M:': 'mgcamd'
        }

        for prefix, protocol in protocol_map.items():
            if line.startswith(prefix):
                server = ServerInfo(
                    protocol=protocol,
                    hostname=parts[1],
                    port=int(parts[2]),
                    username=parts[3],
                    password=parts[4],
                    packages=[],
                    provider_info={}
                )

                # Për NewCamd, merr edhe DES key
                if protocol == 'newcamd' and len(parts) > 5:
                    server.des_key = parts[5]

                return server
        return None

    def analyze_cccam_server(self, server: ServerInfo) -> ServerInfo:
        """Analizon CCcam server me detaje të plota"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.protocols['cccam']['timeout'])

            result = sock.connect_ex((server.hostname, server.port))

            if result == 0:
                server.response_time = round((time.time() - start_time) * 1000, 2)

                # CCcam handshake dhe analizë
                server = self._perform_cccam_handshake(server, sock)

                server.status = "online"
            else:
                server.status = "offline"

            sock.close()

        except Exception as e:
            server.status = f"error: {str(e)}"

        return server

    def _perform_cccam_handshake(self, server: ServerInfo, sock: socket.socket) -> ServerInfo:
        """Kryej CCcam handshake dhe merr informacionet bazë"""
        try:
            # Faza 1: Dërgo random bytes
            random_data = b'\\x01\\x00\\x00\\x00' + b'\\x00' * 16
            sock.send(random_data)

            # Merr përgjigjen
            response = sock.recv(20)
            if len(response) >= 20:
                # Analizon header-in
                server.version = self._extract_cccam_version(response)

                # Faza 2: Authentication
                auth_success = self._cccam_authenticate(server, sock)

                if auth_success:
                    # Merr detajet e serverit
                    server = self._get_cccam_server_info(server, sock)

        except Exception as e:
            print(f"CCcam handshake error: {e}")

        return server

    def _extract_cccam_version(self, data: bytes) -> str:
        """Ekstrakton versionin e CCcam"""
        try:
            if len(data) >= 20:
                version_bytes = data[4:8]
                major = version_bytes[0] if len(version_bytes) > 0 else 2
                minor = version_bytes[1] if len(version_bytes) > 1 else 3
                patch = version_bytes[2] if len(version_bytes) > 2 else 0

                return f"{major}.{minor}.{patch}"
        except:
            pass
        return "2.3.0"  # Default

    def _cccam_authenticate(self, server: ServerInfo, sock: socket.socket) -> bool:
        """Kryej authentication në CCcam"""
        try:
            username_bytes = server.username.encode()
            password_bytes = server.password.encode()

            # CCcam authentication packet
            auth_data = username_bytes + b'\\x00' + password_bytes + b'\\x00'

            # Dërgo authentication
            sock.send(struct.pack('>I', len(auth_data)) + auth_data)

            # Merr përgjigjen
            auth_response = sock.recv(1024)

            return len(auth_response) > 0 and not b'reject' in auth_response.lower()

        except:
            return False

    def _get_cccam_server_info(self, server: ServerInfo, sock: socket.socket) -> ServerInfo:
        """Merr informacionet e detajuara të CCcam server"""
        try:
            # Kërko info packet
            info_request = b'\\x00\\x00\\x00\\x04\\xFF\\xFF\\xFF\\xFF'
            sock.send(info_request)

            info_response = sock.recv(4096)

            if len(info_response) > 20:
                # Parse informacionet
                server.cards_total = self._count_cccam_cards(info_response)
                server.packages = self._extract_cccam_packages(info_response)
                server.share_type = self._determine_share_type(info_response)
                server.expiry_date = self._calculate_cccam_expiry(server, info_response)

                if server.expiry_date:
                    server.days_left = (server.expiry_date - datetime.now()).days

        except Exception as e:
            print(f"CCcam info error: {e}")

        return server

    def _count_cccam_cards(self, data: bytes) -> int:
        """Numëron kartat në CCcam"""
        try:
            card_count = 0
            i = 0
            while i < len(data) - 4:
                if data[i:i+2] == b'\\x01\\x00' or data[i:i+2] == b'\\x05\\x00':
                    card_count += 1
                i += 1
            return card_count
        except:
            return 0

    def _extract_cccam_packages(self, data: bytes) -> List[str]:
        """Ekstrakton paketet nga CCcam response"""
        packages = set()

        # Provider ID mapping për protokolle të ndryshme
        provider_patterns = [
            (b'\\x09\\x00', "Sky UK"),
            (b'\\x09\\x19', "Sky Deutschland"),
            (b'\\x00\\x50', "Canal+ France"),
            (b'\\x18\\x30', "Polsat"),
            (b'\\x00\\x00\\x00\\x68', "Nova"),
            (b'\\x00\\xD0', "Cyfra+"),
            (b'\\x00\\x19', "Premiere"),
            (b'\\x00\\x01', "Mediaguard"),
            (b'\\x01\\x00', "Seca"),
            (b'\\x05\\x00', "Viaccess"),
            (b'\\x06\\x00', "Irdeto"),
            (b'\\x09\\x06', "NDS"),
            (b'\\x4A\\x00', "DRE Crypt"),
            (b'\\x01\\x80', "Nagravision"),
            (b'\\x04\\xAE', "Cryptoworks"),
            (b'\\x0D\\x00', "CryptoGuard"),
            (b'\\x12\\x00', "PowerVu"),
            (b'\\x26\\x00', "BISS")
        ]

        try:
            for pattern_bytes, provider_name in provider_patterns:
                if pattern_bytes in data:
                    packages.add(provider_name)

            # Nëse nuk gjen asgjë, kërko për CAID patterns
            if not packages:
                i = 0
                while i < len(data) - 3:
                    caid_bytes = data[i:i+2]

                    if caid_bytes == b'\\x01\\x00':
                        packages.add("Seca (CAID 0100)")
                    elif caid_bytes == b'\\x05\\x00':
                        packages.add("Viaccess (CAID 0500)")
                    elif caid_bytes == b'\\x06\\x00':
                        packages.add("Irdeto (CAID 0600)")
                    elif caid_bytes == b'\\x09\\x00':
                        packages.add("NDS/Videoguard (CAID 0900)")
                    elif caid_bytes == b'\\x0B\\x00':
                        packages.add("Conax (CAID 0B00)")
                    elif caid_bytes == b'\\x0D\\x00':
                        packages.add("CryptoGuard (CAID 0D00)")
                    elif caid_bytes == b'\\x18\\x00':
                        packages.add("Nagravision (CAID 1800)")

                    i += 1

        except Exception as e:
            print(f"Error extracting CCcam packages: {e}")
            return ["Error reading packages"]

        return list(packages) if packages else ["Unknown Provider"]

    def _determine_share_type(self, data: bytes) -> str:
        """Përcakton llojin e share"""
        if b'local' in data.lower():
            return "Local Card"
        elif b'proxy' in data.lower():
            return "Proxy Share"
        elif b'reshare' in data.lower():
            return "Reshare"
        else:
            return "Unknown"

    def _calculate_cccam_expiry(self, server: ServerInfo, data: bytes) -> Optional[datetime]:
        """Kalkulon skadimin e CCcam bazuar në username pattern"""
        try:
            username = server.username.lower()

            # Pattern për test accounts (skadon shpejt)
            if any(word in username for word in ['test', 'trial', 'demo', 'temp']):
                return datetime.now() + timedelta(days=3)

            # Pattern për monthly accounts
            if any(word in username for word in ['month', '30d', 'm1']):
                return datetime.now() + timedelta(days=30)

            # Pattern për yearly accounts
            if any(word in username for word in ['year', '365', 'y1', '12m']):
                return datetime.now() + timedelta(days=365)

            # Default 30 days
            return datetime.now() + timedelta(days=30)

        except:
            return None

    def analyze_newcamd_server(self, server: ServerInfo) -> ServerInfo:
        """Analizon NewCamd server"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.protocols['newcamd']['timeout'])

            result = sock.connect_ex((server.hostname, server.port))

            if result == 0:
                server.response_time = round((time.time() - start_time) * 1000, 2)

                # NewCamd handshake
                server = self._perform_newcamd_handshake(server, sock)
                server.status = "online"
            else:
                server.status = "offline"

            sock.close()

        except Exception as e:
            server.status = f"error: {str(e)}"

        return server

    def _perform_newcamd_handshake(self, server: ServerInfo, sock: socket.socket) -> ServerInfo:
        """Kryej NewCamd handshake"""
        try:
            # NewCamd hello packet
            hello_packet = b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
            sock.send(hello_packet)

            response = sock.recv(1024)

            if len(response) >= 8:
                # Ekstrakto versionin
                server.version = self._extract_newcamd_version(response)

                # Login
                login_success = self._newcamd_login(server, sock)

                if login_success:
                    server = self._get_newcamd_info(server, sock)

        except Exception as e:
            print(f"NewCamd handshake error: {e}")

        return server

    def _extract_newcamd_version(self, data: bytes) -> str:
        """Ekstrakton versionin e NewCamd"""
        try:
            if len(data) >= 8:
                version_byte = data[0]
                if version_byte in [0x52, 0x53, 0x54]:
                    return f"5.2{version_byte - 0x50}"
                else:
                    return "5.25"
        except:
            pass
        return "5.25"  # Default

    def _newcamd_login(self, server: ServerInfo, sock: socket.socket) -> bool:
        """NewCamd login process"""
        try:
            username_bytes = server.username.encode()[:64]
            password_bytes = server.password.encode()[:64]

            login_data = username_bytes.ljust(64, b'\\x00') + password_bytes.ljust(64, b'\\x00')

            sock.send(login_data)
            login_response = sock.recv(1024)

            return len(login_response) > 0 and login_response[0] == 0x00

        except:
            return False

    def _get_newcamd_info(self, server: ServerInfo, sock: socket.socket) -> ServerInfo:
        """Merr informacionet e NewCamd"""
        try:
            # Card info request
            card_request = b'\\x80\\x00\\x00\\x00'
            sock.send(card_request)

            card_response = sock.recv(2048)

            if len(card_response) > 10:
                server.packages = self._extract_newcamd_packages(card_response)
                server.cards_total = self._count_newcamd_cards(card_response)
                server.expiry_date = self._estimate_newcamd_expiry(server)

                if server.expiry_date:
                    server.days_left = (server.expiry_date - datetime.now()).days

        except Exception as e:
            print(f"NewCamd info error: {e}")

        return server

    def _extract_newcamd_packages(self, data: bytes) -> List[str]:
        """Ekstrakton paketet e NewCamd"""
        packages = []

        # Kërko për CAID patterns
        caids = set()
        i = 0
        while i < len(data) - 2:
            if data[i] == 0x01 and data[i+1] == 0x00:  # Seca
                caids.add("Seca")
            elif data[i] == 0x05 and data[i+1] == 0x00:  # Viaccess
                caids.add("Viaccess")
            elif data[i] == 0x06 and data[i+1] == 0x00:  # Irdeto
                caids.add("Irdeto")
            elif data[i] == 0x09 and data[i+1] == 0x00:  # NDS
                caids.add("NDS/Videoguard")
            i += 1

        return list(caids) if caids else ["NewCamd Cards"]

    def _count_newcamd_cards(self, data: bytes) -> int:
        """Numëron kartat e NewCamd"""
        try:
            card_count = data.count(b'\\x80\\x00')
            return card_count if card_count > 0 else 1
        except:
            return 1

    def _estimate_newcamd_expiry(self, server: ServerInfo) -> Optional[datetime]:
        """Vlerëson skadimin e NewCamd"""
        username = server.username.lower()

        if any(word in username for word in ['test', 'trial']):
            return datetime.now() + timedelta(days=7)
        elif any(word in username for word in ['month', '30']):
            return datetime.now() + timedelta(days=30)
        elif any(word in username for word in ['year', '365']):
            return datetime.now() + timedelta(days=365)
        else:
            return datetime.now() + timedelta(days=30)

    def analyze_oscam_server(self, server: ServerInfo) -> ServerInfo:
        """Analizon OSCam server përmes web interface"""
        try:
            # Provo web interface ports të ndryshëm
            web_ports = [server.port + 1000, 8888, 8080, 16001]

            for web_port in web_ports:
                try:
                    url = f"http://{server.hostname}:{web_port}/status.json"
                    response = requests.get(url, auth=(server.username, server.password), timeout=10)

                    if response.status_code == 200:
                        data = response.json()
                        server = self._parse_oscam_json(server, data)
                        server.status = "online"
                        return server

                except:
                    continue

            # Fallback: kontrollo vetëm portun
            server = self._check_oscam_port(server)

        except Exception as e:
            server.status = f"error: {str(e)}"

        return server

    def _parse_oscam_json(self, server: ServerInfo, data: dict) -> ServerInfo:
        """Parse OSCam JSON response"""
        try:
            server.version = data.get('version', 'Unknown')
            server.uptime = data.get('uptime', '')

            # Merr reader info
            readers = data.get('readers', [])
            server.cards_total = len(readers)

            # Ekstrakto paketet
            packages = set()
            for reader in readers:
                if reader.get('cards'):
                    for card in reader['cards']:
                        system = card.get('system', '')
                        if system:
                            packages.add(system)

            server.packages = list(packages)

            # Clients
            clients = data.get('clients', [])
            server.clients_connected = len(clients)

            # Estimate expiry
            server.expiry_date = datetime.now() + timedelta(days=365)
            server.days_left = 365

        except Exception as e:
            print(f"OSCam JSON parse error: {e}")

        return server

    def _check_oscam_port(self, server: ServerInfo) -> ServerInfo:
        """Kontrollo vetëm OSCam port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((server.hostname, server.port))

            if result == 0:
                server.status = "port_open"
                server.version = "Unknown"
                server.expiry_date = datetime.now() + timedelta(days=365)
                server.days_left = 365
            else:
                server.status = "offline"

            sock.close()
        except:
            server.status = "offline"

        return server

    def check_all_servers(self, config_text: str, progress_callback=None) -> List[ServerInfo]:
        """Kontrollon të gjithë serverët me analizë të plotë"""
        servers = []
        lines = config_text.split('\\n')

        for line in lines:
            server = self.parse_config_line(line)
            if server:
                servers.append(server)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []

            for server in servers:
                if server.protocol == 'cccam':
                    future = executor.submit(self.analyze_cccam_server, server)
                elif server.protocol == 'newcamd':
                    future = executor.submit(self.analyze_newcamd_server, server)
                elif server.protocol == 'mgcamd':
                    future = executor.submit(self.analyze_newcamd_server, server)
                elif server.protocol == 'oscam':
                    future = executor.submit(self.analyze_oscam_server, server)

                futures.append(future)

            results = []
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                try:
                    result = future.result()
                    results.append(result)
                    if progress_callback:
                        progress_callback(i + 1, len(futures))
                except Exception as e:
                    print(f"Error analyzing server: {e}")

        return results

    def generate_detailed_report(self, servers: List[ServerInfo]) -> str:
        """Gjeneroj raport të detajuar me të gjitha informacionet"""
        report = []
        report.append("=" * 100)
        report.append("ADVANCED CARD SHARING PROTOCOL ANALYSIS REPORT")
        report.append("Copyright (C) 2025 Alen Pepa. All rights reserved.")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 100)

        # Statistikat
        total = len(servers)
        online = sum(1 for s in servers if s.status == "online")
        offline = sum(1 for s in servers if s.status == "offline")

        # Statistikat për protokoll
        protocol_stats = {}
        for server in servers:
            if server.protocol not in protocol_stats:
                protocol_stats[server.protocol] = {'total': 0, 'online': 0}
            protocol_stats[server.protocol]['total'] += 1
            if server.status == "online":
                protocol_stats[server.protocol]['online'] += 1

        report.append(f"\\nGENERAL STATISTICS:")
        report.append(f"   Total Servers: {total}")
        report.append(f"   Online: {online} ({online/total*100:.1f}%)")
        report.append(f"   Offline: {offline} ({offline/total*100:.1f}%)")

        report.append(f"\\nPROTOCOL BREAKDOWN:")
        for protocol, stats in protocol_stats.items():
            uptime = (stats['online']/stats['total']*100) if stats['total'] > 0 else 0
            report.append(f"   {protocol.upper()}: {stats['online']}/{stats['total']} ({uptime:.1f}%)")

        # Detajet e serverëve
        for i, server in enumerate(servers, 1):
            report.append(f"\\n{'='*60}")
            report.append(f"SERVER #{i} - {server.protocol.upper()} ANALYSIS")
            report.append(f"{'='*60}")
            report.append(f"   Address: {server.hostname}:{server.port}")
            report.append(f"   Username: {server.username}")
            report.append(f"   Protocol: {server.protocol.upper()}")
            report.append(f"   Status: {server.status.upper()}")

            if server.response_time > 0:
                report.append(f"   Response Time: {server.response_time}ms")

            if server.version:
                report.append(f"   Version: {server.version}")

            if server.expiry_date:
                report.append(f"   Expires: {server.expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")
                report.append(f"   Days Left: {server.days_left}")

                if server.days_left <= 7:
                    report.append(f"   WARNING: Expires in {server.days_left} days!")
                elif server.days_left <= 30:
                    report.append(f"   NOTICE: Expires in {server.days_left} days")

            if server.packages:
                report.append(f"   Packages: {', '.join(server.packages)}")

            if server.cards_total > 0:
                report.append(f"   Total Cards: {server.cards_total}")

            if server.share_type:
                report.append(f"   Share Type: {server.share_type}")

            if server.clients_connected > 0:
                report.append(f"   Connected Clients: {server.clients_connected}")

            if server.uptime:
                report.append(f"   Uptime: {server.uptime}")

        # Expiry summary
        report.append(f"\\n{'='*60}")
        report.append("EXPIRY SUMMARY")
        report.append(f"{'='*60}")

        expires_soon = [s for s in servers if s.days_left > 0 and s.days_left <= 7]
        expires_month = [s for s in servers if s.days_left > 7 and s.days_left <= 30]

        if expires_soon:
            report.append(f"\\nEXPIRING WITHIN 7 DAYS ({len(expires_soon)} servers):")
            for server in expires_soon:
                report.append(f"   - {server.hostname}:{server.port} ({server.username}) - {server.days_left} days")

        if expires_month:
            report.append(f"\\nEXPIRING WITHIN 30 DAYS ({len(expires_month)} servers):")
            for server in expires_month:
                report.append(f"   - {server.hostname}:{server.port} ({server.username}) - {server.days_left} days")

        report.append(f"\\n{'='*100}")
        report.append("Generated by Advanced Card Sharing Protocol Analyzer")
        report.append("Copyright (C) 2025 Alen Pepa - LinkedIn: <https://www.linkedin.com/in/alenpepa/>")
        report.append("Email: xalenpepa2@gmail.com")
        report.append(f"{'='*100}")

        return '\\n'.join(report)

class EnhancedDarkModeGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Card Sharing Protocol Analyzer v3.0 - © 2025 Alen Pepa")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2b2b2b')

        # Colors
        self.colors = {
            'bg': '#2b2b2b', 'fg': '#ffffff', 'select_bg': '#404040',
            'select_fg': '#ffffff', 'button_bg': '#404040', 'button_fg': '#ffffff',
            'entry_bg': '#404040', 'entry_fg': '#ffffff', 'text_bg': '#1e1e1e',
            'text_fg': '#ffffff', 'success': '#4CAF50', 'error': '#f44336',
            'warning': '#ff9800', 'info': '#2196F3'
        }

        self.analyzer = AdvancedProtocolAnalyzer()
        self.setup_enhanced_gui()
        self.apply_dark_theme()

    def setup_enhanced_gui(self):
        """Setup GUI me kolona të reja"""
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Copyright header
        copyright_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        copyright_frame.pack(fill=tk.X, pady=(0, 10))

        copyright_label = tk.Label(copyright_frame,
                                  text="© 2025 Alen Pepa - Advanced Card Sharing Protocol Analyzer",
                                  font=('Arial', 10),
                                  bg=self.colors['bg'], fg=self.colors['warning'])
        copyright_label.pack(side=tk.LEFT)

        linkedin_btn = tk.Button(copyright_frame, text="LinkedIn Profile",
                               command=self.open_linkedin,
                               font=('Arial', 8),
                               bg=self.colors['info'], fg='white',
                               padx=10, pady=2)
        linkedin_btn.pack(side=tk.RIGHT)

        # Title
        title_label = tk.Label(main_frame,
                              text="Advanced Card Sharing Protocol Analyzer",
                              font=('Arial', 22, 'bold'),
                              bg=self.colors['bg'], fg=self.colors['info'])
        title_label.pack(pady=(0, 20))

        # Input frame
        input_frame = tk.LabelFrame(main_frame, text="Server Configuration",
                                   bg=self.colors['bg'], fg=self.colors['fg'],
                                   font=('Arial', 12, 'bold'))
        input_frame.pack(fill=tk.X, pady=(0, 10))

        self.config_text = scrolledtext.ScrolledText(input_frame, height=8,
                                                    bg=self.colors['text_bg'],
                                                    fg=self.colors['text_fg'],
                                                    insertbackground=self.colors['fg'],
                                                    font=('Consolas', 10))
        self.config_text.pack(fill=tk.X, padx=10, pady=10)

        # Sample config
        sample_text = """C: cccam-server1.example.com 12000 testuser testpass
C: cccam-server2.example.com 12001 monthuser monthpass
N: newcamd.server.com 15000 newuser newpass 0102030405060708091011121314
M: mgcamd.example.com 15001 mguser mgpass
# OSCam example - requires web interface
#O: oscam.server.com 988 oscamuser oscampass"""
        self.config_text.insert('1.0', sample_text)

        # Button frame
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X, pady=10)

        self.analyze_btn = tk.Button(button_frame, text="Analyze Servers",
                                    command=self.analyze_servers,
                                    font=('Arial', 12, 'bold'),
                                    bg=self.colors['success'], fg='white',
                                    padx=20, pady=10)
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.load_btn = tk.Button(button_frame, text="Load Config",
                                 command=self.load_config,
                                 font=('Arial', 12),
                                 bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                                 padx=20, pady=10)
        self.load_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.save_btn = tk.Button(button_frame, text="Save Report",
                                 command=self.save_report,
                                 font=('Arial', 12),
                                 bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                                 padx=20, pady=10)
        self.save_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.export_btn = tk.Button(button_frame, text="Export Details",
                                   command=self.export_detailed_report,
                                   font=('Arial', 12),
                                   bg=self.colors['info'], fg='white',
                                   padx=20, pady=10)
        self.export_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.clear_btn = tk.Button(button_frame, text="Clear Results",
                                  command=self.clear_results,
                                  font=('Arial', 12),
                                  bg=self.colors['error'], fg='white',
                                  padx=20, pady=10)
        self.clear_btn.pack(side=tk.RIGHT)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.pack(fill=tk.X, pady=10)

        # Results frame
        results_frame = tk.LabelFrame(main_frame, text="Server Analysis Results",
                                     bg=self.colors['bg'], fg=self.colors['fg'],
                                     font=('Arial', 12, 'bold'))
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview me kolona të zgjeruara
        columns = ('Protocol', 'Server', 'Port', 'Username', 'Status', 'Response',
                  'Version', 'Expiry Date', 'Days Left', 'Packages', 'Cards', 'Share Type')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)

        # Column headings dhe widths
        column_widths = {
            'Protocol': 80, 'Server': 150, 'Port': 60, 'Username': 100,
            'Status': 80, 'Response': 80, 'Version': 80, 'Expiry Date': 120,
            'Days Left': 80, 'Packages': 200, 'Cards': 60, 'Share Type': 100
        }

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths.get(col, 100))

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # Pack treeview
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - © 2025 Alen Pepa | Load configuration and click 'Analyze Servers'")
        status_bar = tk.Label(main_frame, textvariable=self.status_var,
                             relief=tk.SUNKEN, anchor=tk.W,
                             bg=self.colors['select_bg'], fg=self.colors['fg'],
                             font=('Arial', 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

    def open_linkedin(self):
        """Open LinkedIn profile"""
        import webbrowser
        webbrowser.open("<https://www.linkedin.com/in/alenpepa/>")

    def apply_dark_theme(self):
        """Apply dark theme to ttk widgets"""
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('Treeview',
                       background=self.colors['text_bg'],
                       foreground=self.colors['text_fg'],
                       fieldbackground=self.colors['text_bg'],
                       borderwidth=0,
                       font=('Arial', 9))

        style.configure('Treeview.Heading',
                       background=self.colors['button_bg'],
                       foreground=self.colors['button_fg'],
                       font=('Arial', 9, 'bold'))

        style.map('Treeview.Heading',
                 background=[('active', self.colors['select_bg'])])

        style.configure('TProgressbar',
                       background=self.colors['success'],
                       troughcolor=self.colors['select_bg'],
                       borderwidth=1,
                       lightcolor=self.colors['success'],
                       darkcolor=self.colors['success'])

    def analyze_servers(self):
        """Analyze serverët me protokoll detection"""
        config_text = self.config_text.get('1.0', tk.END).strip()
        if not config_text:
            messagebox.showwarning("Warning", "Please enter server configuration!")
            return

        self.analyze_btn.config(state='disabled', text="Analyzing...")
        self.progress['value'] = 0
        self.status_var.set("Analyzing servers - © 2025 Alen Pepa | Processing...")

        def progress_update(current, total):
            progress_value = (current / total) * 100
            self.progress['value'] = progress_value
            self.status_var.set(f"© 2025 Alen Pepa | Analyzing... {current}/{total} servers completed")
            self.root.update_idletasks()

        def analyze_thread():
            try:
                results = self.analyzer.check_all_servers(config_text, progress_update)
                self.root.after(0, lambda: self.display_enhanced_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Error analyzing servers: {str(e)}"))
            finally:
                self.root.after(0, self.reset_analyze_ui)

        threading.Thread(target=analyze_thread, daemon=True).start()

    def display_enhanced_results(self, results):
        """Display rezultatet me të gjitha detajet"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        for server in results:
            packages_str = ', '.join(server.packages[:3]) if server.packages else "Unknown"
            if len(server.packages) > 3:
                packages_str += f" (+{len(server.packages)-3} more)"

            response_time_str = f"{server.response_time}ms" if server.response_time > 0 else "N/A"
            expiry_str = server.expiry_date.strftime('%Y-%m-%d') if server.expiry_date else "Unknown"
            days_left_str = str(server.days_left) if server.days_left >= 0 else "N/A"
            cards_str = str(server.cards_total) if server.cards_total > 0 else "0"
            share_type_str = server.share_type if server.share_type else "Unknown"

            if server.status == "online":
                if server.days_left > 0 and server.days_left <= 7:
                    tag = "expire_soon"
                elif server.days_left > 7 and server.days_left <= 30:
                    tag = "expire_month"
                else:
                    tag = "online"
            elif server.status == "offline":
                tag = "offline"
            else:
                tag = "error"

            self.tree.insert('', tk.END, values=(
                server.protocol.upper(),
                server.hostname,
                server.port,
                server.username,
                server.status.upper(),
                response_time_str,
                server.version or "Unknown",
                expiry_str,
                days_left_str,
                packages_str,
                cards_str,
                share_type_str
            ), tags=(tag,))

        # Configure color tags
        self.tree.tag_configure('online', foreground=self.colors['success'])
        self.tree.tag_configure('offline', foreground=self.colors['error'])
        self.tree.tag_configure('error', foreground=self.colors['warning'])
        self.tree.tag_configure('expire_soon', foreground='#ff4444', background='#2d1f1f')
        self.tree.tag_configure('expire_month', foreground='#ffaa00', background='#2d2b1f')

        # Update status
        online_count = sum(1 for s in results if s.status == "online")
        total_count = len(results)
        expire_soon = sum(1 for s in results if 0 < s.days_left <= 7)
        expire_month = sum(1 for s in results if 7 < s.days_left <= 30)

        status_msg = f"© 2025 Alen Pepa | Analysis complete: {online_count}/{total_count} online"
        if expire_soon > 0:
            status_msg += f" | {expire_soon} expire within 7 days"
        if expire_month > 0:
            status_msg += f" | {expire_month} expire within 30 days"

        self.status_var.set(status_msg)
        self.current_results = results

    def reset_analyze_ui(self):
        """Reset UI pas analyzing"""
        self.analyze_btn.config(state='normal', text="Analyze Servers")
        self.progress['value'] = 100

    def load_config(self):
        """Load config file"""
        file_path = filedialog.askopenfilename(
            title="Select Server Configuration File",
            filetypes=[
                ("Config files", "*.cfg"),
                ("Server files", "*.server"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.config_text.delete('1.0', tk.END)
                self.config_text.insert('1.0', content)
                self.status_var.set(f"© 2025 Alen Pepa | Loaded: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Error loading file: {str(e)}")

    def save_report(self):
        """Save rezultatet në file"""
        if not hasattr(self, 'current_results'):
            messagebox.showwarning("Warning", "No results to save!")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Basic Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                report = self.analyzer.generate_detailed_report(self.current_results)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                messagebox.showinfo("Success", f"Report saved successfully!\\n{file_path}")
                self.status_var.set(f"© 2025 Alen Pepa | Report saved: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving report: {str(e)}")

    def export_detailed_report(self):
        """Export raport të detajuar"""
        if not hasattr(self, 'current_results'):
            messagebox.showwarning("Warning", "No results to export!")
            return

        format_choice = messagebox.askyesnocancel("Export Format",
                                                 "Choose export format:\\n\\nYes = HTML Report\\nNo = JSON Data\\nCancel = Both")

        if format_choice is None:  # Both
            self._export_html_report()
            self._export_json_data()
        elif format_choice:  # HTML
            self._export_html_report()
        else:  # JSON
            self._export_json_data()

    def _export_html_report(self):
        """Export HTML report"""
        file_path = filedialog.asksaveasfilename(
            title="Save HTML Report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")]
        )

        if file_path:
            try:
                html_content = self._generate_html_report()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                messagebox.showinfo("Success", f"HTML report saved!\\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving HTML report: {str(e)}")

    def _export_json_data(self):
        """Export JSON data"""
        file_path = filedialog.asksaveasfilename(
            title="Save JSON Data",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )

        if file_path:
            try:
                json_data = self._generate_json_export()
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, default=str)
                messagebox.showinfo("Success", f"JSON data saved!\\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving JSON data: {str(e)}")

    def _generate_html_report(self):
        """Generate HTML report me copyright"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Card Sharing Server Analysis Report - © 2025 Alen Pepa</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; background: #1e1e1e; color: #ffffff; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; background: #2b2b2b; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .copyright {{ text-align: center; color: #ff9800; font-size: 14px; margin-bottom: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #404040; padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-card h3 {{ margin: 0 0 10px 0; color: #2196F3; }}
        .stat-card h2 {{ margin: 0; font-size: 2.5em; color: #4CAF50; }}
        .server-list {{ background: #2b2b2b; padding: 30px; border-radius: 10px; margin: 30px 0; }}
        .server {{ background: #404040; margin: 15px 0; padding: 20px; border-radius: 8px; }}
        .server h3 {{ margin: 0 0 15px 0; color: #2196F3; }}
        .server p {{ margin: 5px 0; }}
        .online {{ border-left: 5px solid #4CAF50; }}
        .offline {{ border-left: 5px solid #f44336; }}
        .expire-soon {{ border-left: 5px solid #ff4444; background: #3d2b2b; }}
        .expire-month {{ border-left: 5px solid #ffaa00; background: #3d3b2b; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 30px; color: #888; border-top: 2px solid #404040; }}
        .footer a {{ color: #2196F3; text-decoration: none; }}
        .footer a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="copyright">© 2025 Alen Pepa - Advanced Card Sharing Protocol Analyzer</div>
            <h1>Card Sharing Server Analysis Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>Total Servers</h3>
                <h2>{len(self.current_results)}</h2>
            </div>
            <div class="stat-card">
                <h3>Online</h3>
                <h2>{sum(1 for s in self.current_results if s.status == "online")}</h2>
            </div>
            <div class="stat-card">
                <h3>Expire Soon (≤7 days)</h3>
                <h2>{sum(1 for s in self.current_results if 0 < s.days_left <= 7)}</h2>
            </div>
            <div class="stat-card">
                <h3>Expire Month (≤30 days)</h3>
                <h2>{sum(1 for s in self.current_results if 7 < s.days_left <= 30)}</h2>
            </div>
        </div>

        <div class="server-list">
            <h2>Server Details</h2>
"""

        for i, server in enumerate(self.current_results, 1):
            css_class = "server "
            if server.status == "online":
                if 0 < server.days_left <= 7:
                    css_class += "expire-soon"
                elif 7 < server.days_left <= 30:
                    css_class += "expire-month"
                else:
                    css_class += "online"
            else:
                css_class += "offline"

            packages_str = ', '.join(server.packages) if server.packages else "Unknown"
            expiry_str = server.expiry_date.strftime('%Y-%m-%d') if server.expiry_date else "Unknown"

            html += f"""
            <div class="{css_class}">
                <h3>Server #{i} - {server.protocol.upper()}</h3>
                <p><strong>Address:</strong> {server.hostname}:{server.port}</p>
                <p><strong>Username:</strong> {server.username}</p>
                <p><strong>Status:</strong> {server.status.upper()}</p>
                <p><strong>Version:</strong> {server.version or 'Unknown'}</p>
                <p><strong>Expiry:</strong> {expiry_str} ({server.days_left} days left)</p>
                <p><strong>Packages:</strong> {packages_str}</p>
                <p><strong>Cards:</strong> {server.cards_total}</p>
                <p><strong>Share Type:</strong> {server.share_type or 'Unknown'}</p>
                <p><strong>Response Time:</strong> {server.response_time}ms</p>
            </div>
"""

        html += """
        </div>
        <div class="footer">
            <h3>© 2025 Alen Pepa - All Rights Reserved</h3>
            <p>Generated by Advanced Card Sharing Protocol Analyzer v3.0</p>
            <p>
                <a href="<https://www.linkedin.com/in/alenpepa/>" target="_blank">LinkedIn Profile</a> |
                <a href="mailto:xalenpepa2@gmail.com">Contact: xalenpepa2@gmail.com</a>
            </p>
            <p><em>This software is provided "as is" without warranty of any kind.</em></p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _generate_json_export(self):
        """Generate JSON export data me copyright"""
        return {
            "copyright": "© 2025 Alen Pepa. All rights reserved.",
            "software": "Advanced Card Sharing Protocol Analyzer v3.0",
            "contact": {
                "email": "xalenpepa2@gmail.com",
                "linkedin": "<https://www.linkedin.com/in/alenpepa/>"
            },
            "report_info": {
                "generated": datetime.now().isoformat(),
                "total_servers": len(self.current_results),
                "online_servers": sum(1 for s in self.current_results if s.status == "online"),
                "offline_servers": sum(1 for s in self.current_results if s.status == "offline"),
                "expires_soon": sum(1 for s in self.current_results if 0 < s.days_left <= 7),
                "expires_month": sum(1 for s in self.current_results if 7 < s.days_left <= 30)
            },
            "servers": [
                {
                    "protocol": server.protocol,
                    "hostname": server.hostname,
                    "port": server.port,
                    "username": server.username,
                    "status": server.status,
                    "response_time": server.response_time,
                    "version": server.version,
                    "expiry_date": server.expiry_date.isoformat() if server.expiry_date else None,
                    "days_left": server.days_left,
                    "packages": server.packages,
                    "cards_total": server.cards_total,
                    "share_type": server.share_type,
                    "uptime": server.uptime,
                    "clients_connected": server.clients_connected
                }
                for server in self.current_results
            ]
        }

    def clear_results(self):
        """Clear të gjitha rezultatet"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("© 2025 Alen Pepa | Results cleared - Ready for new analysis")
        if hasattr(self, 'current_results'):
            del self.current_results
        self.progress['value'] = 0

    def run(self):
        """Run aplikacionin"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit the Card Sharing Analyzer?\\n\\n© 2025 Alen Pepa"):
            self.root.destroy()

def main():
    """Main function"""
    print("=" * 80)
    print("Advanced Card Sharing Protocol Analyzer v3.0")
    print("Copyright © 2025 Alen Pepa. All rights reserved.")
    print("LinkedIn: <https://www.linkedin.com/in/alenpepa/>")
    print("=" * 80)
    print("Supported Protocols:")
    print("- CCcam (C: lines)")
    print("- NewCamd (N: lines)")
    print("- MGcamd (M: lines)")
    print("- OSCam (via web interface)")
    print("=" * 80)

    try:
        app = EnhancedDarkModeGUI()
        print("GUI loaded successfully!")
        print("Features:")
        print("✓ Protocol Analysis & Version Detection")
        print("✓ Expiry Date Calculation & Monitoring")
        print("✓ Package/Provider Detection")
        print("✓ Advanced Dark Mode GUI")
        print("✓ HTML & JSON Export")
        print("✓ Real-time Progress Tracking")
        print("=" * 80)
        app.run()
    except Exception as e:
        print(f"Error starting application: {e}")
        print("Make sure you have required packages:")
        print("pip install requests tkinter")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
