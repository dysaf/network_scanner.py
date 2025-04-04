import scapy.all as scapy
import nmap
import subprocess
import requests
import time
import tkinter as tk
from tkinter import messagebox

def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
    except requests.exceptions.RequestException:
        pass
    return "Unknown Vendor"

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        mac_vendor = get_mac_vendor(element[1].hwsrc)
        devices.append({
            "IP": element[1].psrc,
            "MAC": element[1].hwsrc,
            "Vendor": mac_vendor
        })
    return devices

def scan_wifi():
    print("Scanning nearby Wi-Fi Access Points...")
    subprocess.call(["sudo", "airodump-ng", "wlan0"])

def weak_password_scan(target_ip):
    print(f"Starting brute-force attack on {target_ip}...")
    subprocess.call(["hydra", "-l", "admin", "-P", "/path/to/passwords.txt", f"ssh://{target_ip}"])

def vuln_scan(target_ip):
    print(f"Scanning for vulnerabilities on {target_ip}...")
    subprocess.call(["sudo", "nmap", "--script", "vuln", "-p", "22,80,443", target_ip])

def live_monitoring(ip_range):
    print("Monitoring devices on the network...")
    while True:
        devices = scan_network(ip_range)
        print("\nDevices on the network:")
        for device in devices:
            print(f"IP: {device['IP']}, MAC: {device['MAC']}, Vendor: {device['Vendor']}")
        time.sleep(10)

def start_scan():
    ip_range = ip_range_entry.get()
    live_monitoring(ip_range)

app = tk.Tk()
app.title("Network Device Scanner")

tk.Label(app, text="Enter Network IP Range (e.g., 192.168.1.0/24)").pack(padx=10, pady=10)
ip_range_entry = tk.Entry(app, width=30)
ip_range_entry.pack(padx=10, pady=10)

scan_button = tk.Button(app, text="Start Scan", command=start_scan)
scan_button.pack(pady=20)

app.mainloop()
