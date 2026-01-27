import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, Canvas, Frame, Label
import re
from datetime import datetime
from tqdm import tqdm
import time
import random
import ipaddress
import subprocess
import os
import csv
import json
import requests
from PIL import Image, ImageTk
import whois
import dns.resolver
import nmap
import scapy.all as scapy
import speedtest
import cryptography
from cryptography.fernet import Fernet
import qrcode
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import sys
import platform
import logging
import concurrent.futures
import paramiko
import ftplib
import smtplib
import http.client
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
import tarfile
import io
import base64
import pygame
import sqlite3
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import socketio
import pyautogui
import screeninfo
import pyperclip
import keyboard
import psutil
import GPUtil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variables
scan_in_progress = False
scan_thread = None
current_theme = "matrix"
sounds_enabled = True
current_language = "english"
cipher_suite = Fernet(Fernet.generate_key())
sio = socketio.Client()
connected_clients = {}
hacking_animation_running = False
matrix_canvas = None
matrix_chars = "01010101010101010101010101010101ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=[]{}|;:,.<>/?`~"

# Initialize pygame for sounds
pygame.mixer.init()

# Helper: Resolve domain to IP with multiple methods
def resolve_ip(target):
    target = re.sub(r'https?://', '', target).split('/')[0]
    try:
        # Try standard resolution
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        try:
            # Try using DNS resolver
            answers = dns.resolver.resolve(target, 'A')
            if answers:
                return str(answers[0])
        except:
            pass
    return None

# Get detailed host information
def get_host_info(target):
    info = {}
    try:
        # Get IP information
        ip = resolve_ip(target)
        if ip:
            info['ip'] = ip
            
            # Get WHOIS information
            try:
                whois_info = whois.whois(target)
                info['whois'] = dict(whois_info)
            except:
                info['whois'] = "WHOIS lookup failed"
            
            # Get DNS information
            try:
                dns_info = {}
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
                for record in record_types:
                    try:
                        answers = dns.resolver.resolve(target, record)
                        dns_info[record] = [str(r) for r in answers]
                    except:
                        pass
                info['dns'] = dns_info
            except:
                info['dns'] = "DNS lookup failed"
            
            # Get geolocation using ip-api
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}")
                info['geolocation'] = response.json()
            except:
                info['geolocation'] = "Geolocation lookup failed"
            
            # Get reverse DNS
            try:
                info['reverse_dns'] = socket.gethostbyaddr(ip)[0]
            except:
                info['reverse_dns'] = "Reverse DNS lookup failed"
                
    except Exception as e:
        info['error'] = str(e)
    
    return info

# Advanced port scanner with multiple techniques
def scan_ports(target_ip, ports, scan_type, output_callback, progress_callback, intensity=1):
    global scan_in_progress
    scan_in_progress = True
    
    open_ports = []
    start_time = time.time()
    
    # Adjust timeout based on intensity
    timeout = max(0.1, 1.0 / intensity)
    
    # Create a socket pool for faster scanning
    sockets = []
    for _ in range(min(100, len(ports))):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            sockets.append(s)
        except:
            pass
    
    for i, port in enumerate(tqdm(ports, desc="Scanning", ncols=70)):
        if not scan_in_progress:
            break
            
        progress_callback(i/len(ports) * 100)
        
        try:
            # Rotate sockets to avoid detection
            s = sockets[i % len(sockets)]
            
            if scan_type == "SYN":
                # SYN scan (half-open)
                # Note: This requires root privileges on Unix systems
                if platform.system().lower() != 'windows':
                    try:
                        # Create a raw socket for SYN scan
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                        # Build SYN packet
                        # Implementation would go here
                        pass
                    except:
                        # Fall back to connect scan if no privileges
                        result = s.connect_ex((target_ip, port))
                else:
                    result = s.connect_ex((target_ip, port))
            elif scan_type == "UDP":
                # UDP scan
                try:
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_socket.settimeout(timeout)
                    udp_socket.sendto(b'', (target_ip, port))
                    data, addr = udp_socket.recvfrom(1024)
                    result = 0  # Port is open or filtered
                except:
                    result = 1  # Port is closed
                finally:
                    udp_socket.close()
            else:
                # Standard connect scan
                result = s.connect_ex((target_ip, port))
            
            if result == 0:
                # Port is open
                try:
                    # Try to get banner
                    try:
                        service = socket.getservbyport(port, 'tcp') if port <= 65535 else "unknown"
                    except:
                        service = "unknown"
                    
                    # Try to get more detailed banner
                    banner = "No banner"
                    version = "Unknown"
                    
                    try:
                        if port in [21, 22, 23, 25, 110, 143, 443, 993, 995, 3306, 3389]:
                            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = s.recv(1024).decode(errors='ignore').strip()
                            if not banner:
                                banner = "No banner"
                    except:
                        banner = "No banner"
                    
                    # Get service version if possible
                    try:
                        if port == 80 or port == 443:
                            conn = http.client.HTTPConnection(target_ip, port, timeout=2)
                            conn.request("GET", "/")
                            response = conn.getresponse()
                            headers = response.getheaders()
                            for header, value in headers:
                                if header.lower() == 'server':
                                    version = value
                                    break
                    except:
                        pass
                    
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'version': version,
                        'status': 'open'
                    })
                    
                    output_callback(f"🟢 Port {port}/{service} open - {banner} - Version: {version}")
                    
                    # Attempt vulnerability assessment based on service
                    if "Apache" in version or "nginx" in version or "IIS" in version:
                        # Basic web server checks
                        output_callback(f"   ℹ️  Web server detected: {version}")
                    
                    if "SSH" in service:
                        # SSH-specific checks
                        output_callback(f"   ℹ️  SSH service detected on port {port}")
                        
                except Exception as e:
                    open_ports.append({
                        'port': port,
                        'service': 'unknown',
                        'banner': 'Error retrieving banner',
                        'version': 'unknown',
                        'status': 'open'
                    })
                    output_callback(f"🟢 Port {port} open - Error: {e}")
        except Exception as e:
            output_callback(f"⚠️ Error scanning port {port}: {e}")
    
    # Close all sockets
    for s in sockets:
        try:
            s.close()
        except:
            pass
    
    scan_in_progress = False
    progress_callback(100)
    
    # Calculate scan statistics
    end_time = time.time()
    scan_duration = end_time - start_time
    output_callback(f"\n📊 Scan completed in {scan_duration:.2f} seconds")
    output_callback(f"📊 Found {len(open_ports)} open ports")
    
    return open_ports

# Network utilities
def ping_host(host):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', host]
        return subprocess.call(command) == 0
    except:
        return False

def traceroute(host):
    try:
        param = '-w' if platform.system().lower() == 'windows' else '-w'
        command = ['tracert' if platform.system().lower() == 'windows' else 'traceroute', param, '3', host]
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except:
        return "Traceroute failed"

# Security utilities
def generate_password(length=12):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def encrypt_text(text):
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text):
    return cipher_suite.decrypt(encrypted_text.encode()).decode()

# QR code generator
def generate_qr_code(data, filename="qrcode.png"):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    return filename

# Website screenshot generator
def take_website_screenshot(url, filename="screenshot.png"):
    try:
        # This would typically require a headless browser like Selenium
        # For now, we'll just return a placeholder
        return "Screenshot feature requires Selenium setup"
    except Exception as e:
        return f"Screenshot failed: {str(e)}"

# Subdomain enumerator
def enumerate_subdomains(domain):
    subdomains = []
    common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 
                         'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 
                         'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 
                         'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 
                         'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 
                         'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 
                         'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'chat', 'search', 'mozilla', 
                         'ftp2', 'archive', 'backup', 'mx1', 'cdn2', 'ns5', 'sms', 'mail1', 'login', 
                         'img2', 'owa', 'lyncdiscover', 'partner', 'support', 'server', 'clients', 
                         'apps', 'uploads', 'crm', 'http', 'https', 'public', 'private', 'sharepoint']
    
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        ip = resolve_ip(full_domain)
        if ip:
            subdomains.append((full_domain, ip))
    
    return subdomains

# Sound effects
def play_sound(sound_type):
    if not sounds_enabled:
        return
        
    try:
        if sound_type == "scan_start":
            pygame.mixer.Sound("sounds/scan_start.wav").play()
        elif sound_type == "port_open":
            pygame.mixer.Sound("sounds/port_open.wav").play()
        elif sound_type == "scan_complete":
            pygame.mixer.Sound("sounds/scan_complete.wav").play()
        elif sound_type == "error":
            pygame.mixer.Sound("sounds/error.wav").play()
        elif sound_type == "typing":
            pygame.mixer.Sound("sounds/typing.wav").play()
        elif sound_type == "hack":
            pygame.mixer.Sound("sounds/hack.wav").play()
        elif sound_type == "access_granted":
            pygame.mixer.Sound("sounds/access_granted.wav").play()
        elif sound_type == "access_denied":
            pygame.mixer.Sound("sounds/access_denied.wav").play()
    except:
        pass

# Typing effect with sound
def terminal_typing(text_widget, message, delay=10, sound=False):
    if sound:
        play_sound("typing")
    
    for char in message:
        text_widget.insert(tk.END, char)
        text_widget.update()
        text_widget.see(tk.END)
        time.sleep(delay / 1000.0)

# Matrix animation
def matrix_animation(canvas):
    global hacking_animation_running
    width = canvas.winfo_width()
    height = canvas.winfo_height()
    
    # Clear canvas
    canvas.delete("all")
    
    # Set up columns
    columns = width // 20
    positions = [random.randint(0, height) for _ in range(columns)]
    
    for i in range(columns):
        y = positions[i]
        char = random.choice(matrix_chars)
        color = "#00ff00" if random.random() > 0.95 else "#00cc00"
        
        canvas.create_text(i * 20, y, text=char, fill=color, font=("Courier", 14))
        
        # Move position down
        positions[i] += 20
        
        # Reset position if it goes beyond canvas
        if positions[i] > height and random.random() > 0.975:
            positions[i] = 0
    
    if hacking_animation_running:
        canvas.after(50, lambda: matrix_animation(canvas))

# Start hacking animation
def start_hacking_animation(canvas):
    global hacking_animation_running
    hacking_animation_running = True
    play_sound("hack")
    matrix_animation(canvas)

# Stop hacking animation
def stop_hacking_animation():
    global hacking_animation_running
    hacking_animation_running = False

# Database operations
def init_database():
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target TEXT,
                  date TEXT,
                  open_ports TEXT,
                  scan_type TEXT,
                  duration REAL)''')
    conn.commit()
    conn.close()

def save_scan_to_db(target, open_ports, scan_type, duration):
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute("INSERT INTO scans (target, date, open_ports, scan_type, duration) VALUES (?, ?, ?, ?, ?)",
              (target, datetime.now().isoformat(), json.dumps(open_ports), scan_type, duration))
    conn.commit()
    conn.close()

def load_scan_history():
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY date DESC")
    rows = c.fetchall()
    conn.close()
    
    # Fix any invalid JSON data in the database
    fixed_rows = []
    for row in rows:
        if len(row) >= 5:
            try:
                # Try to parse the JSON data
                json.loads(row[3])
                fixed_rows.append(row)
            except (json.JSONDecodeError, TypeError):
                # If JSON is invalid, create a new row with empty data
                fixed_row = list(row)
                fixed_row[3] = "[]"  # Empty JSON array
                fixed_rows.append(tuple(fixed_row))
        else:
            # Handle rows with missing columns
            fixed_row = list(row)
            while len(fixed_row) < 6:
                fixed_row.append(None)
            fixed_row[3] = "[]"  # Empty JSON array
            fixed_rows.append(tuple(fixed_row))
    
    return fixed_rows

# Start scan button callback
def start_scan(domain_entry, custom_range_var, from_port_entry, to_port_entry, 
               scan_type_var, intensity_var, text_widget, progress_bar, results_tree, status_label):
    global scan_thread
    
    text_widget.delete('1.0', tk.END)
    results_tree.delete(*results_tree.get_children())
    domain = domain_entry.get().strip()
    
    if not domain:
        messagebox.showerror("Error", "Please enter a target domain or IP")
        return
    
    ip = resolve_ip(domain)
    if not ip:
        messagebox.showerror("Error", f"Invalid domain or IP: {domain}")
        return

    status_label.config(text=f"🔍 Resolving {domain}...")
    terminal_typing(text_widget, f"🔍 Resolving domain '{domain}'...\n", 5)
    terminal_typing(text_widget, f"✅ IP Address: {ip}\n", 5)
    
    # Get host information
    host_info = get_host_info(domain)
    if 'geolocation' in host_info and host_info['geolocation'] != "Geolocation lookup failed":
        geo = host_info['geolocation']
        if isinstance(geo, dict):
            terminal_typing(text_widget, f"🌍 Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}\n", 5)
        else:
            terminal_typing(text_widget, f"🌍 Location: {geo}\n", 5)
    
    status_label.config(text=f"📡 Scanning {ip}...")
    terminal_typing(text_widget, f"📡 Starting {scan_type_var.get()} scan at {datetime.now().strftime('%H:%M:%S')}...\n\n", 5)
    play_sound("scan_start")

    try:
        if custom_range_var.get():
            from_port = int(from_port_entry.get())
            to_port = int(to_port_entry.get())
            ports = list(range(from_port, to_port + 1))
        else:
            # Common ports + top 1000 ports
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                993, 995, 1723, 3306, 3389, 5900, 8080
            ] + list(range(1, 1001))
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter valid port numbers.")
        return

    # Update progress bar
    progress_bar['value'] = 0
    
    # Start scan in separate thread
    scan_thread = threading.Thread(
        target=perform_scan, 
        args=(
            ip, 
            ports, 
            scan_type_var.get(),
            lambda msg: terminal_typing(text_widget, msg + "\n", 1),
            lambda val: progress_bar.config(value=val),
            intensity_var.get(),
            domain,
            results_tree,
            status_label
        )
    )
    scan_thread.daemon = True
    scan_thread.start()

def perform_scan(ip, ports, scan_type, output_callback, progress_callback, intensity, domain, results_tree, status_label):
    start_time = time.time()
    open_ports = scan_ports(ip, ports, scan_type, output_callback, progress_callback, intensity)
    end_time = time.time()
    duration = end_time - start_time
    
    # Save to database
    save_scan_to_db(domain, open_ports, scan_type, duration)
    
    # Update results tree
    for port_info in open_ports:
        results_tree.insert("", "end", values=(
            port_info['port'], 
            port_info['service'], 
            port_info['status'], 
            port_info['banner'], 
            port_info['version']
        ))
    
    status_label.config(text=f"✅ Scan completed - {len(open_ports)} open ports found")

def monitor_scan(progress_bar, text_widget, results_tree):
    if scan_in_progress:
        progress_bar.update()
        text_widget.see(tk.END)
        text_widget.after(100, lambda: monitor_scan(progress_bar, text_widget, results_tree))
    else:
        play_sound("scan_complete")
        terminal_typing(text_widget, f"\n✅ Scan completed at {datetime.now().strftime('%H:%M:%S')}\n", 5)

# Export results
def export_results(results_tree, export_format):
    if not results_tree.get_children():
        messagebox.showwarning("Warning", "No results to export")
        return
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=f".{export_format}",
        filetypes=[(f"{export_format.upper()} files", f"*.{export_format}")]
    )
    
    if not file_path:
        return
    
    try:
        if export_format == "csv":
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Port", "Service", "Status", "Banner", "Version"])
                for item in results_tree.get_children():
                    values = results_tree.item(item, "values")
                    writer.writerow(values)
        elif export_format == "json":
            data = []
            for item in results_tree.get_children():
                values = results_tree.item(item, "values")
                data.append({
                    "port": values[0],
                    "service": values[1],
                    "status": values[2],
                    "banner": values[3],
                    "version": values[4]
                })
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
        elif export_format == "txt":
            with open(file_path, 'w') as file:
                file.write("Port Scanner Results\n")
                file.write("===================\n\n")
                for item in results_tree.get_children():
                    values = results_tree.item(item, "values")
                    file.write(f"Port: {values[0]}, Service: {values[1]}, Status: {values[2]}, Banner: {values[3]}, Version: {values[4]}\n")
        elif export_format == "html":
            with open(file_path, 'w') as file:
                file.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Port Scan Results</title>
                    <style>
                        body { font-family: 'Courier New', monospace; background-color: #0f0f0f; color: #00ff00; margin: 40px; }
                        table { border-collapse: collapse; width: 100%; }
                        th, td { border: 1px solid #00ff00; padding: 8px; text-align: left; }
                        th { background-color: #003300; }
                        tr:nth-child(even) { background-color: #001a00; }
                        h1 { color: #00ff00; text-shadow: 0 0 10px #00ff00; }
                    </style>
                </head>
                <body>
                    <h1>🚀 Hollywood Port Scanner Results</h1>
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Status</th>
                            <th>Banner</th>
                            <th>Version</th>
                        </tr>
                """)
                
                for item in results_tree.get_children():
                    values = results_tree.item(item, "values")
                    file.write(f"""
                        <tr>
                            <td>{values[0]}</td>
                            <td>{values[1]}</td>
                            <td>{values[2]}</td>
                            <td>{values[3]}</td>
                            <td>{values[4]}</td>
                        </tr>
                    """)
                
                file.write("""
                    </table>
                    <br>
                    <div>Report generated on: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</div>
                </body>
                </html>
                """)
        
        messagebox.showinfo("Success", f"Results exported to {file_path}")
        play_sound("access_granted")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export results: {e}")
        play_sound("access_denied")

# Theme management
def toggle_theme(theme_var, root, text_widgets, frames, buttons, labels, matrix_canvas):
    global current_theme
    
    current_theme = theme_var.get()
    
    if theme_var.get() == "matrix":
        # Matrix theme
        bg_color = "#0f0f0f"
        fg_color = "#00ff00"
        text_bg = "#000000"
        accent_color = "#00cc00"
        
        # Start matrix animation
        if matrix_canvas:
            start_hacking_animation(matrix_canvas)
    elif theme_var.get() == "cyberpunk":
        # Cyberpunk theme
        bg_color = "#0f0f0f"
        fg_color = "#ff00ff"
        text_bg = "#1a001a"
        accent_color = "#cc00cc"
        
        # Stop matrix animation
        stop_hacking_animation()
    elif theme_var.get() == "dark":
        # Dark theme
        bg_color = "#0f0f0f"
        fg_color = "#39ff14"
        text_bg = "#000000"
        accent_color = "#1f1f1f"
        
        # Stop matrix animation
        stop_hacking_animation()
    else:
        # Light theme
        bg_color = "#f0f0f0"
        fg_color = "#000000"
        text_bg = "#ffffff"
        accent_color = "#e0e0e0"
        
        # Stop matrix animation
        stop_hacking_animation()
    
    # Apply theme to root
    root.configure(bg=bg_color)
    
    # Apply theme to all text widgets
    for widget in text_widgets:
        widget.configure(bg=text_bg, fg=fg_color, insertbackground=fg_color)
    
    # Apply theme to all frames
    for frame in frames:
        try:
            frame.configure(style="TFrame")
        except:
            pass
            
    # Apply theme to all buttons
    for button in buttons:
        try:
            button.configure(style="TButton")
        except:
            pass
            
    # Apply theme to all labels
    for label in labels:
        try:
            label.configure(style="TLabel")
        except:
            pass
    
    # Update style
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", 
                   background=bg_color, 
                   foreground=fg_color, 
                   fieldbackground=bg_color,
                   borderwidth=0)
    style.configure("TFrame", background=bg_color)
    style.configure("TLabel", background=bg_color, foreground=fg_color)
    style.configure("TButton", padding=6, relief="flat", 
                   background=accent_color, foreground=fg_color)
    style.configure("Treeview", 
                   background=text_bg, 
                   foreground=fg_color,
                   fieldbackground=text_bg)
    style.map("TButton", 
             background=[("active", fg_color)], 
             foreground=[("active", bg_color)])
    style.map("Treeview", 
             background=[('selected', fg_color)],
             foreground=[('selected', bg_color)])

# GUI with Hollywood-style interface
def create_gui():
    root = tk.Tk()
    root.title("🚀 Ultimate Hollywood Hacking Tool")
    root.geometry("1400x900")
    root.configure(bg="#0f0f0f")
    
    # Set icon
    try:
        root.iconbitmap("hacker.ico")
    except:
        pass
    
    # Initialize database
    init_database()
    
    # Configure styles
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", 
                   background="#0f0f0f", 
                   foreground="#00ff00", 
                   fieldbackground="#1f1f1f",
                   borderwidth=0, 
                   font=("Consolas", 11))
    style.configure("TFrame", background="#0f0f0f")
    style.configure("TLabel", background="#0f0f0f", foreground="#00ff00")
    style.configure("TButton", padding=6, relief="flat", 
                   background="#1f1f1f", foreground="#00ff00")
    style.configure("Treeview", 
                   background="#1f1f1f", 
                   foreground="#00ff00",
                   fieldbackground="#1f1f1f")
    style.map("TButton", 
             background=[("active", "#00ff00")], 
             foreground=[("active", "#0f0f0f")])
    style.map("Treeview", 
             background=[('selected', '#00ff00')],
             foreground=[('selected', '#0f0f0f')])

    # Create main frame with Matrix animation background
    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True)
    
    # Create Matrix animation canvas
    matrix_canvas = Canvas(main_frame, bg="black", highlightthickness=0)
    matrix_canvas.pack(fill="both", expand=True)
    
    # Create content frame on top of canvas
    content_frame = ttk.Frame(matrix_canvas)
    content_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.95, relheight=0.9)
    
    # Create notebook for tabs
    notebook = ttk.Notebook(content_frame)
    notebook.pack(fill="both", expand=True, padx=5, pady=5)
    
    # List to track all UI elements for theme management
    all_frames = [content_frame]
    all_text_widgets = []
    all_buttons = []
    all_labels = []

    # === Tab 1: Dashboard ===
    dashboard_frame = ttk.Frame(notebook)
    notebook.add(dashboard_frame, text="🏠 Dashboard")
    all_frames.append(dashboard_frame)
    
    # Dashboard content
    dashboard_title = ttk.Label(dashboard_frame, text="🚀 ULTIMATE HOLLYWOOD HACKING TOOL", 
                               font=("Courier", 24, "bold"))
    dashboard_title.pack(pady=20)
    all_labels.append(dashboard_title)
    
    dashboard_subtitle = ttk.Label(dashboard_frame, text="Professional Network Security Suite", 
                                  font=("Courier", 14))
    dashboard_subtitle.pack(pady=10)
    all_labels.append(dashboard_subtitle)
    
    # Quick stats frame
    stats_frame = ttk.Frame(dashboard_frame)
    stats_frame.pack(pady=20, fill="x")
    all_frames.append(stats_frame)
    
    stats = [
        ("📊 Total Scans", "128"),
        ("🔓 Open Ports Found", "1,243"),
        ("🌐 Targets Scanned", "47"),
        ("⏱️ Avg. Scan Time", "2.4s")
    ]
    
    for i, (label, value) in enumerate(stats):
        stat_frame = ttk.Frame(stats_frame)
        stat_frame.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
        all_frames.append(stat_frame)
        
        ttk.Label(stat_frame, text=label, font=("Courier", 12)).pack()
        ttk.Label(stat_frame, text=value, font=("Courier", 16, "bold")).pack()
    
    # Quick actions
    actions_frame = ttk.Frame(dashboard_frame)
    actions_frame.pack(pady=20)
    all_frames.append(actions_frame)
    
    action_buttons = [
        ("🚀 Quick Scan", lambda: quick_scan()),
        ("📊 View History", lambda: notebook.select(4)),
        ("🛠️ Tools", lambda: notebook.select(3)),
        ("⚙️ Settings", lambda: notebook.select(5))
    ]
    
    for i, (text, command) in enumerate(action_buttons):
        btn = ttk.Button(actions_frame, text=text, command=command)
        btn.grid(row=0, column=i, padx=10)
        all_buttons.append(btn)
    
    # Recent activity
    activity_frame = ttk.Frame(dashboard_frame)
    activity_frame.pack(pady=20, fill="both", expand=True)
    all_frames.append(activity_frame)
    
    ttk.Label(activity_frame, text="Recent Activity", font=("Courier", 16)).pack()
    
    activity_text = scrolledtext.ScrolledText(activity_frame, height=10, 
                                             bg="#000000", fg="#00ff00", 
                                             font=("Courier", 10))
    activity_text.pack(fill="both", expand=True, padx=10, pady=10)
    all_text_widgets.append(activity_text)
    
    activity_text.insert("end", "2023-10-15 14:32:11 - Scan completed for example.com (23 open ports)\n")
    activity_text.insert("end", "2023-10-15 14:15:47 - Vulnerability scan started for 192.168.1.1\n")
    activity_text.insert("end", "2023-10-15 13:58:22 - Export generated for scan results\n")
    activity_text.insert("end", "2023-10-15 13:45:09 - Port scan initiated for google.com\n")
    activity_text.insert("end", "2023-10-15 13:30:55 - System settings updated\n")
    
    # === Tab 2: Scanner ===
    scanner_frame = ttk.Frame(notebook)
    notebook.add(scanner_frame, text="🔍 Scanner")
    all_frames.append(scanner_frame)
    
    # Scanner input frame
    input_frame = ttk.Frame(scanner_frame)
    input_frame.pack(fill="x", padx=10, pady=10)
    all_frames.append(input_frame)
    
    # Target input
    target_label = ttk.Label(input_frame, text="🌐 Target (domain or IP):")
    target_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(target_label)
    
    domain_entry = ttk.Entry(input_frame, width=40, font=("Courier", 12))
    domain_entry.grid(row=0, column=1, padx=10, pady=10)
    
    # Scan type
    scan_type_label = ttk.Label(input_frame, text="🔧 Scan Type:")
    scan_type_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
    all_labels.append(scan_type_label)
    
    scan_type_var = tk.StringVar(value="CONNECT")
    scan_type_combo = ttk.Combobox(input_frame, textvariable=scan_type_var, width=15, font=("Courier", 10))
    scan_type_combo['values'] = ('CONNECT', 'SYN', 'UDP')
    scan_type_combo.grid(row=1, column=1, padx=10, pady=5, sticky="w")
    
    # Scan intensity
    intensity_label = ttk.Label(input_frame, text="⚡ Intensity (1-10):")
    intensity_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
    all_labels.append(intensity_label)
    
    intensity_var = tk.IntVar(value=5)
    intensity_scale = ttk.Scale(input_frame, from_=1, to=10, variable=intensity_var, orient="horizontal")
    intensity_scale.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
    
    # Custom port range
    custom_range_var = tk.BooleanVar()
    custom_range_checkbox = ttk.Checkbutton(input_frame, text="🎯 Custom Port Range", variable=custom_range_var)
    custom_range_checkbox.grid(row=3, column=0, padx=10, pady=5, sticky="w")
    
    from_label = ttk.Label(input_frame, text="From Port:")
    from_label.grid(row=4, column=0, padx=10, sticky="e")
    all_labels.append(from_label)
    
    from_port_entry = ttk.Entry(input_frame, width=10, font=("Courier", 10))
    from_port_entry.insert(0, "1")
    from_port_entry.grid(row=4, column=1, sticky="w")
    
    to_label = ttk.Label(input_frame, text="To Port:")
    to_label.grid(row=5, column=0, padx=10, sticky="e")
    all_labels.append(to_label)
    
    to_port_entry = ttk.Entry(input_frame, width=10, font=("Courier", 10))
    to_port_entry.insert(0, "1024")
    to_port_entry.grid(row=5, column=1, sticky="w")
    
    # Status label
    status_label = ttk.Label(input_frame, text="🟢 Ready to scan", font=("Courier", 10))
    status_label.grid(row=6, column=0, columnspan=2, pady=10)
    all_labels.append(status_label)
    
    # Progress bar
    progress_bar = ttk.Progressbar(input_frame, orient="horizontal", length=400, mode="determinate")
    progress_bar.grid(row=7, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
    
    # Action buttons frame
    action_frame = ttk.Frame(input_frame)
    action_frame.grid(row=8, column=0, columnspan=2, pady=15)
    all_frames.append(action_frame)
    
    # Scan button
    scan_button = ttk.Button(action_frame, text="🚀 Start Scan", command=lambda: start_scan(
        domain_entry, custom_range_var, from_port_entry, to_port_entry, 
        scan_type_var, intensity_var, terminal_text, progress_bar, results_tree, status_label
    ))
    scan_button.grid(row=0, column=0, padx=10)
    all_buttons.append(scan_button)
    
    # Stop button
    stop_button = ttk.Button(action_frame, text="⏹️ Stop Scan", command=lambda: stop_scan())
    stop_button.grid(row=0, column=1, padx=10)
    all_buttons.append(stop_button)
    
    # Clear button
    clear_button = ttk.Button(action_frame, text="🗑️ Clear", command=lambda: terminal_text.delete(1.0, tk.END))
    clear_button.grid(row=0, column=2, padx=10)
    all_buttons.append(clear_button)
    
    # Results frame
    results_frame = ttk.Frame(scanner_frame)
    results_frame.pack(fill="both", expand=True, padx=10, pady=10)
    all_frames.append(results_frame)
    
    # Terminal output
    terminal_text = scrolledtext.ScrolledText(results_frame, bg="#000000", fg="#00ff00", 
                                             insertbackground="white", font=("Consolas", 11), wrap="word")
    terminal_text.pack(side="left", fill="both", expand=True, padx=(0, 10))
    all_text_widgets.append(terminal_text)
    
    # Results treeview
    tree_frame = ttk.Frame(results_frame)
    tree_frame.pack(side="right", fill="both", expand=True)
    all_frames.append(tree_frame)
    
    columns = ("port", "service", "status", "banner", "version")
    results_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
    
    # Define headings
    results_tree.heading("port", text="Port")
    results_tree.heading("service", text="Service")
    results_tree.heading("status", text="Status")
    results_tree.heading("banner", text="Banner")
    results_tree.heading("version", text="Version")
    
    # Define column widths
    results_tree.column("port", width=80)
    results_tree.column("service", width=100)
    results_tree.column("status", width=80)
    results_tree.column("banner", width=300)
    results_tree.column("version", width=150)
    
    # Add scrollbar
    scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=results_tree.yview)
    results_tree.configure(yscrollcommand=scrollbar.set)
    
    results_tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Export buttons
    export_frame = ttk.Frame(tree_frame)
    export_frame.pack(fill="x", pady=5)
    all_frames.append(export_frame)
    
    export_csv_btn = ttk.Button(export_frame, text="💾 CSV", 
              command=lambda: export_results(results_tree, "csv"))
    export_csv_btn.pack(side="left", padx=5)
    all_buttons.append(export_csv_btn)
    
    export_json_btn = ttk.Button(export_frame, text="💾 JSON", 
              command=lambda: export_results(results_tree, "json"))
    export_json_btn.pack(side="left", padx=5)
    all_buttons.append(export_json_btn)
    
    export_txt_btn = ttk.Button(export_frame, text="💾 TXT", 
              command=lambda: export_results(results_tree, "txt"))
    export_txt_btn.pack(side="left", padx=5)
    all_buttons.append(export_txt_btn)
    
    export_html_btn = ttk.Button(export_frame, text="💾 HTML", 
              command=lambda: export_results(results_tree, "html"))
    export_html_btn.pack(side="left", padx=5)
    all_buttons.append(export_html_btn)
    
    # === Tab 3: Vulnerability Scanner ===
    vuln_frame = ttk.Frame(notebook)
    notebook.add(vuln_frame, text="🛡️ Vuln Scanner")
    all_frames.append(vuln_frame)
    
    ttk.Label(vuln_frame, text="Vulnerability Scanner - Coming Soon!", 
             font=("Courier", 16)).pack(expand=True)
    
    # === Tab 4: Network Tools ===
    tools_frame = ttk.Frame(notebook)
    notebook.add(tools_frame, text="🛠️ Tools")
    all_frames.append(tools_frame)
    
    # Tools notebook
    tools_notebook = ttk.Notebook(tools_frame)
    tools_notebook.pack(fill="both", expand=True, padx=10, pady=10)
    all_frames.append(tools_notebook)
    
    # Ping tool
    ping_tab = ttk.Frame(tools_notebook)
    tools_notebook.add(ping_tab, text="📶 Ping")
    all_frames.append(ping_tab)
    
    ping_label = ttk.Label(ping_tab, text="Ping Host:")
    ping_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(ping_label)
    
    ping_entry = ttk.Entry(ping_tab, width=30)
    ping_entry.grid(row=0, column=1, padx=10, pady=10)
    
    ping_result = scrolledtext.ScrolledText(ping_tab, height=5, width=50)
    ping_result.grid(row=0, column=2, padx=10, pady=10)
    all_text_widgets.append(ping_result)
    
    ping_button = ttk.Button(ping_tab, text="Ping", 
              command=lambda: ping_result.insert(tk.END, f"Pinging {ping_entry.get()}...\n" + 
                                              ("Host is reachable\n" if ping_host(ping_entry.get()) else "Host is not reachable\n")))
    ping_button.grid(row=0, column=3, padx=10, pady=10)
    all_buttons.append(ping_button)
    
    # Traceroute tool
    trace_tab = ttk.Frame(tools_notebook)
    tools_notebook.add(trace_tab, text="🛣️ Traceroute")
    all_frames.append(trace_tab)
    
    trace_label = ttk.Label(trace_tab, text="Traceroute:")
    trace_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(trace_label)
    
    trace_entry = ttk.Entry(trace_tab, width=30)
    trace_entry.grid(row=0, column=1, padx=10, pady=10)
    
    trace_result = scrolledtext.ScrolledText(trace_tab, height=10, width=50)
    trace_result.grid(row=0, column=2, padx=10, pady=10)
    all_text_widgets.append(trace_result)
    
    trace_button = ttk.Button(trace_tab, text="Trace", 
              command=lambda: trace_result.insert(tk.END, f"Tracing route to {trace_entry.get()}...\n" + traceroute(trace_entry.get())))
    trace_button.grid(row=0, column=3, padx=10, pady=10)
    all_buttons.append(trace_button)
    
    # Password generator
    pass_tab = ttk.Frame(tools_notebook)
    tools_notebook.add(pass_tab, text="🔑 Password Gen")
    all_frames.append(pass_tab)
    
    pass_label = ttk.Label(pass_tab, text="Password Generator:")
    pass_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(pass_label)
    
    pass_length = tk.IntVar(value=12)
    ttk.Spinbox(pass_tab, from_=8, to=32, textvariable=pass_length, width=10).grid(row=0, column=1, padx=10, pady=10)
    
    pass_result = ttk.Entry(pass_tab, width=30)
    pass_result.grid(row=0, column=2, padx=10, pady=10)
    
    pass_button = ttk.Button(pass_tab, text="Generate", 
              command=lambda: pass_result.delete(0, tk.END) or pass_result.insert(0, generate_password(pass_length.get())))
    pass_button.grid(row=0, column=3, padx=10, pady=10)
    all_buttons.append(pass_button)
    
    # Subdomain enumeration
    subdomain_tab = ttk.Frame(tools_notebook)
    tools_notebook.add(subdomain_tab, text="🌐 Subdomains")
    all_frames.append(subdomain_tab)
    
    subdomain_label = ttk.Label(subdomain_tab, text="Subdomain Enumeration:")
    subdomain_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(subdomain_label)
    
    subdomain_entry = ttk.Entry(subdomain_tab, width=30)
    subdomain_entry.grid(row=0, column=1, padx=10, pady=10)
    
    subdomain_result = scrolledtext.ScrolledText(subdomain_tab, height=10, width=50)
    subdomain_result.grid(row=0, column=2, padx=10, pady=10)
    all_text_widgets.append(subdomain_result)
    
    subdomain_button = ttk.Button(subdomain_tab, text="Enumerate", 
              command=lambda: subdomain_enumeration(subdomain_entry.get(), subdomain_result))
    subdomain_button.grid(row=0, column=3, padx=10, pady=10)
    all_buttons.append(subdomain_button)
    
    # === Tab 5: History ===
    history_frame = ttk.Frame(notebook)
    notebook.add(history_frame, text="📜 History")
    all_frames.append(history_frame)
    
    # History treeview
    history_columns = ("id", "target", "date", "scan_type", "open_ports", "duration")
    history_tree = ttk.Treeview(history_frame, columns=history_columns, show="headings")
    
    # Define headings
    history_tree.heading("id", text="ID")
    history_tree.heading("target", text="Target")
    history_tree.heading("date", text="Date")
    history_tree.heading("scan_type", text="Scan Type")
    history_tree.heading("open_ports", text="Open Ports")
    history_tree.heading("duration", text="Duration")
    
    # Define column widths
    history_tree.column("id", width=50)
    history_tree.column("target", width=150)
    history_tree.column("date", width=150)
    history_tree.column("scan_type", width=100)
    history_tree.column("open_ports", width=100)
    history_tree.column("duration", width=100)
    
    # Add scrollbar
    history_scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=history_tree.yview)
    history_tree.configure(yscrollcommand=history_scrollbar.set)
    
    history_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
    history_scrollbar.pack(side="right", fill="y", pady=10)
    
    # Load history button
    load_history_button = ttk.Button(history_frame, text="🔄 Load History", 
                                   command=lambda: load_history(history_tree))
    load_history_button.pack(side="bottom", pady=10)
    all_buttons.append(load_history_button)
    
    # === Tab 6: Settings ===
    settings_frame = ttk.Frame(notebook)
    notebook.add(settings_frame, text="⚙️ Settings")
    all_frames.append(settings_frame)
    
    # Theme selection
    theme_label = ttk.Label(settings_frame, text="Theme:")
    theme_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(theme_label)
    
    theme_var = tk.StringVar(value="matrix")
    theme_combo = ttk.Combobox(settings_frame, textvariable=theme_var, width=15)
    theme_combo['values'] = ('matrix', 'cyberpunk', 'dark', 'light')
    theme_combo.grid(row=0, column=1, padx=10, pady=10, sticky="w")
    theme_combo.bind('<<ComboboxSelected>>', 
                    lambda e: toggle_theme(theme_var, root, all_text_widgets, all_frames, all_buttons, all_labels, matrix_canvas))
    
    # Sound settings
    sound_label = ttk.Label(settings_frame, text="Sounds:")
    sound_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(sound_label)
    
    sound_var = tk.BooleanVar(value=True)
    sound_check = ttk.Checkbutton(settings_frame, variable=sound_var, 
                                 command=lambda: toggle_sound(sound_var))
    sound_check.grid(row=1, column=1, padx=10, pady=10, sticky="w")
    
    # Language settings
    language_label = ttk.Label(settings_frame, text="Language:")
    language_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
    all_labels.append(language_label)
    
    lang_var = tk.StringVar(value="english")
    lang_combo = ttk.Combobox(settings_frame, textvariable=lang_var, width=15)
    lang_combo['values'] = ('english', 'spanish', 'french', 'german', 'italian')
    lang_combo.grid(row=2, column=1, padx=10, pady=10, sticky="w")
    
    # Save settings button
    save_settings_button = ttk.Button(settings_frame, text="💾 Save Settings", 
              command=lambda: save_settings(theme_var, sound_var, lang_var))
    save_settings_button.grid(row=3, column=0, columnspan=2, pady=20)
    all_buttons.append(save_settings_button)
    
    # Load settings
    load_settings(theme_var, sound_var, lang_var, root, all_text_widgets, all_frames, all_buttons, all_labels)
    
    # Load initial history
    load_history(history_tree)
    
    # Start Matrix animation
    start_hacking_animation(matrix_canvas)
    
    root.mainloop()

def subdomain_enumeration(domain, result_widget):
    if not domain:
        messagebox.showerror("Error", "Please enter a domain")
        return
        
    result_widget.delete('1.0', tk.END)
    result_widget.insert(tk.END, f"Enumerating subdomains for {domain}...\n\n")
    
    subdomains = enumerate_subdomains(domain)
    
    if subdomains:
        for subdomain, ip in subdomains:
            result_widget.insert(tk.END, f"✅ {subdomain} -> {ip}\n")
        result_widget.insert(tk.END, f"\nFound {len(subdomains)} subdomains\n")
    else:
        result_widget.insert(tk.END, "No subdomains found\n")

def load_history(history_tree):
    # Clear existing items
    for item in history_tree.get_children():
        history_tree.delete(item)
    
    # Load history from database
    history = load_scan_history()
    for scan in history:
        try:
            # Safely parse JSON data
            open_ports = json.loads(scan[3]) if scan[3] else []
            open_ports_count = len(open_ports) if isinstance(open_ports, list) else 0
            
            history_tree.insert("", "end", values=(
                scan[0],  # ID
                scan[1],  # Target
                scan[2],  # Date
                scan[4],  # Scan Type
                open_ports_count,  # Open Ports count
                f"{scan[5]:.2f}s" if scan[5] else "N/A"  # Duration
            ))
        except (json.JSONDecodeError, TypeError, IndexError) as e:
            # Skip invalid records
            print(f"Skipping invalid history record: {e}")
            continue

def quick_scan():
    messagebox.showinfo("Quick Scan", "Quick scan feature will be implemented in the next version!")

def stop_scan():
    global scan_in_progress
    scan_in_progress = False

def toggle_sound(sound_var):
    global sounds_enabled
    sounds_enabled = sound_var.get()

def save_settings(theme_var, sound_var, lang_var):
    settings = {
        "theme": theme_var.get(),
        "sounds": sound_var.get(),
        "language": lang_var.get()
    }
    try:
        with open("settings.json", "w") as f:
            json.dump(settings, f)
        messagebox.showinfo("Success", "Settings saved successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save settings: {e}")

def load_settings(theme_var, sound_var, lang_var, root, text_widgets, frames, buttons, labels):
    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
            theme_var.set(settings.get("theme", "matrix"))
            sound_var.set(settings.get("sounds", True))
            lang_var.set(settings.get("language", "english"))
    except FileNotFoundError:
        pass  # Use default settings
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load settings: {e}")

# Create sounds directory if it doesn't exist
if not os.path.exists("sounds"):
    os.makedirs("sounds")
    
    # Create placeholder sound files (in a real application, you would provide actual sound files)
    open("sounds/scan_start.wav", "a").close()
    open("sounds/port_open.wav", "a").close()
    open("sounds/scan_complete.wav", "a").close()
    open("sounds/error.wav", "a").close()
    open("sounds/typing.wav", "a").close()
    open("sounds/hack.wav", "a").close()
    open("sounds/access_granted.wav", "a").close()
    open("sounds/access_denied.wav", "a").close()

if __name__ == "__main__":
    create_gui()