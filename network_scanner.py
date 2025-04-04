import argparse
import scapy.all as scapy
import socket
import nmap
import requests

# Function to get vendor (manufacturer) of a device using MAC address
def get_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown Vendor"
    except:
        return "Vendor Lookup Failed"

# Function to perform network scan
def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    print("\nIP Address\t\tMAC Address\t\tManufacturer")
    print("-" * 70)
    devices = []
    for response in answered_list:
        ip = response[1].psrc
        mac = response[1].hwsrc
        vendor = get_vendor(mac)
        devices.append((ip, mac, vendor))
        print(f"{ip}\t\t{mac}\t{vendor}")
    
    return devices

# Function to perform port scanning on a device
def port_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024', '-sV')  # Scan common ports (1-1024) with version detection
    print(f"\n[+] Scanning Open Ports on {ip}...")
    
    for protocol in scanner[ip].all_protocols():
        ports = scanner[ip][protocol].keys()
        for port in sorted(ports):
            service = scanner[ip][protocol][port]['name']
            print(f"Port {port} ({service}) is open")

# Function to detect OS using Nmap
def os_detection(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments="-O")  # OS Detection flag
    print(f"\n[+] Detecting OS for {ip}...")

    try:
        os_info = scanner[ip]['osmatch'][0]['name']
        print(f"OS Detected: {os_info}")
    except:
        print("OS Detection Failed")

# Setting up argument parsing
parser = argparse.ArgumentParser(description="A Network Scanner with Device Detection, OS Identification, and Port Scanning.")
parser.add_argument("-t", "--target", help="Specify the target IP range (e.g., 192.168.1.0/24)", required=True)
parser.add_argument("-p", "--ports", help="Scan open ports of a specific device", action="store_true")
parser.add_argument("-o", "--osdetect", help="Detect the OS of a specific device", action="store_true")

args = parser.parse_args()

# Run the network scan
devices = scan(args.target)

# If additional scanning options are requested, ask user for the IP to scan
if args.ports or args.osdetect:
    target_ip = input("\nEnter the IP address of the target device for further analysis: ")
    if args.ports:
        port_scan(target_ip)
    if args.osdetect:
        os_detection(target_ip)
