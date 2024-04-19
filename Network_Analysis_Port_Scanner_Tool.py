#!/usr/bin/env python3

import speedtest
import os
import socket
import argparse
import sys
import platform
import subprocess
import logging
import psutil
import time

# Configure logging
logging.basicConfig(filename='network_analysis.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s: %(message)s')

logging.info("Script started")

# Function to display a loading visual
def show_loading(message, duration=5):
    print(message, end="")
    for _ in range(duration):
        print(".", end="", flush=True)
        time.sleep(1)
    print("\n")

# Function to test network speed
def test_network_speed():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 1024 / 1024  # Convert to Mbps
        upload_speed = st.upload() / 1024 / 1024  # Convert to Mbps
        print("Network Speed Test Results:")
        print(f"Download Speed: {download_speed:.2f} Mbps")
        print(f"Upload Speed: {upload_speed:.2f} Mbps")
    except Exception as e:
        error_msg = f"Error while testing network speed: {str(e)}"
        print(error_msg)
        logging.error(error_msg)

# Function to analyze Wi-Fi signal strength for both Windows and Linux
def analyze_wifi_signal_strength():
    try:
        if platform.system() == 'Windows':
            signal_strength_info = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
        elif platform.system() == 'Linux':
            signal_strength_info = os.popen("iw dev | grep signal").read()
        elif platform.system() == 'Darwin':
            signal_strength_info = os.popen("iw dev | grep signal").read()    
        else:
            raise Exception("Unsupported operating system for Wi-Fi signal strength analysis")

        print("Wi-Fi Signal Strength Analysis:")
        print(signal_strength_info)
    except Exception as e:
        error_msg = f"Error while analyzing Wi-Fi signal strength: {str(e)}"
        print(error_msg)
        logging.error(error_msg)

# Port descriptions
port_descriptions = {
    21: "FTP - File Transfer Protocol (Unencrypted file transfers, can be intercepted)",
    22: "SSH - Secure Shell (Secure logins, file transfers, often targeted for brute force attacks)",
    23: "Telnet (Insecure data transfer, not encrypted)",
    25: "SMTP - Simple Mail Transfer Protocol (Email routing, often targeted for spam and phishing attacks)",
    53: "DNS - Domain Name System (Can be exploited for DNS amplification attacks)",
    80: "HTTP - Hypertext Transfer Protocol (Unencrypted web traffic, vulnerable to eavesdropping)",
    69: "TFTP - Trivial File Transfer Protocol (Used for transferring files without authentication, often used in boot services)",
    110: "POP3 - Post Office Protocol v3 (Email clients, unencrypted traffic can be intercepted)",
    135: "RPC - Windows RPC services (Can be vulnerable to various attacks if exposed)",
    139: "NetBIOS - Windows file sharing (Often targeted by malware)",
    143: "IMAP - Internet Message Access Protocol (Unencrypted traffic can be intercepted)",
    443: "HTTPS - HTTP Secure (Encrypted web traffic, targeted in advanced attacks)",
    445: "SMB - Server Message Block (Windows file sharing, targeted by malware like WannaCry)",
    3306: "MySQL - Database server port (Can be targeted for database exploitation)",
    3389: "RDP - Remote Desktop Protocol (Often targeted for brute force attacks and unauthorized access)",
    5900: "VNC - Virtual Network Computing (Remote desktop control, often targeted if not properly secured)"
}

# Function to check for open ports on a target IP address and provide descriptions
def check_open_ports(target_ip, ports_to_check):
    try:
        open_ports = []
        for port in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        if open_ports:
            print(f"Open ports on target IP ({target_ip}):")
            for port in open_ports:
                description = port_descriptions.get(port, "No specific security info available")
                print(f"Port {port} is open - {description}")
        else:
            print(f"No open ports found on target IP ({target_ip})")
    except Exception as e:
        error_msg = f"Error while checking open ports: {str(e)}"
        print(error_msg)
        logging.error(error_msg)

# Function to save analysis results to a file
def save_results_to_file(results, filename):
    try:
        with open(filename, 'w') as file:
            for line in results:
                file.write(line + '\n')
        print(f"Analysis results saved to {filename}")
    except Exception as e:
        error_msg = f"Error while saving results to {filename}: {str(e)}"
        print(error_msg)
        logging.error(error_msg)

# Function to get system information
def get_system_info():
    try:
        system_info = {
            'Operating System': platform.system(),
            'OS Release': platform.release(),
            'OS Version': platform.version(),
            'Machine': platform.machine(),
            'Processor': platform.processor(),
            'CPU Count': psutil.cpu_count(logical=True),
            'Memory': f"{psutil.virtual_memory().total / (1024**3):.2f} GB"
        }
        return system_info
    except Exception as e:
        error_msg = f"Error while gathering system information: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
        return {}

# Revised function to auto-detect all network interfaces
def auto_detect_interfaces():
    try:
        interfaces = []
        if platform.system() == 'Windows':
            cmd = 'Get-NetAdapter | Select-Object -ExpandProperty Name'
            output = subprocess.check_output(['powershell', cmd], shell=True, text=True)
            interfaces = output.strip().split('\n')
        elif platform.system() == 'Linux':
            interfaces = os.popen("ls /sys/class/net").read().strip().split('\n')
        elif platform.system() == 'Darwin':
            interfaces = os.popen("ifconfig -l").read().strip().split()
        return interfaces
    except Exception as e:
        error_msg = f"Error while auto-detecting network interfaces: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
        return []

# Custom analysis function
def custom_analysis(interfaces, ports):
    # Implement the custom analysis logic here
    pass

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Network Analysis Script")
        parser.add_argument("--custom", action="store_true", help="Customize analysis options")
        parser.add_argument("--auto-check", action="store_true", help="Auto-check available network interfaces")
        parser.add_argument("--output-file", help="Specify a file to save analysis results")

        args = parser.parse_args()

        system_info = get_system_info()
        print("System Information:")
        for key, value in system_info.items():
            print(f"{key}: {value}")
        print("-" * 30)

        interfaces = auto_detect_interfaces()

        if args.custom:
            custom_ports = input("Enter custom port range (e.g., 80,443,22): ").split(',')
            custom_ports = [int(port) for port in custom_ports]
            custom_analysis(interfaces, custom_ports)
        else:
            # Update the list of ports to check
            extended_ports_to_check = [21, 22, 23, 25, 53, 69, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5900]
            
# Add TFTP and Port 69

            # Using the updated check_open_ports function
            target_ip = socket.gethostbyname(socket.gethostname())
            show_loading("Testing network speed, please wait")
            test_network_speed()
            print("-" * 30)
            
            show_loading("Analyzing Wi-Fi signal strength, please wait")
            analyze_wifi_signal_strength()
            print("-" * 30)
            
            show_loading("Checking open ports, please wait")
            check_open_ports(target_ip, extended_ports_to_check)
            print("-" * 30)

        if args.output_file:
            save_results_to_file([], args.output_file)
        
        print("Network Analysis Completed.")
    except KeyboardInterrupt:
        print("\nNetwork analysis interrupted by the user.")
    except Exception as e:
        error_msg = f"Error during network analysis: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
        
        
