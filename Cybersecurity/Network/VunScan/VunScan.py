import socket
import netifaces as ni
from ipaddress import ip_network
import nmap
from fpdf import FPDF
from tqdm import tqdm
import time
import json
from colorama import Fore, Style, init
import generate_html_report

# Initialize colorama to enable colors in the terminal
init(autoreset=True)

# Function to automatically discover the network range
def get_network_range():
    # Get the default network interface IP
    gws = ni.gateways()
    default_interface = gws['default'][ni.AF_INET][1]  # Default interface (like eth0, wlan0)
    
    # Get the IP and mask of the network interface
    iface = ni.ifaddresses(default_interface)[ni.AF_INET][0]
    ip_addr = iface['addr']
    netmask = iface['netmask']
    
    # Calculate network range using mask
    network = ip_network(f"{ip_addr}/{netmask}", strict=False)
    
    return str(network)

# Function to discover active hosts on the network
def discover_active_hosts(network_range):
    nm = nmap.PortScanner()
    print(f"Discovering hosts in network {network_range}...")
    
    nm.scan(hosts=network_range, arguments='-sn')
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']

    return active_hosts

# Function to scan ports, services and vulnerabilities
def scan_active_hosts(active_hosts):
    nm = nmap.PortScanner()
    scan_results = {}

    # Add progress bar
    for host in tqdm(active_hosts, desc="Scanning hosts", unit="host"):
        time.sleep(0.5)  # Simulates waiting time
        # Add NSE script for vulnerabilities (-sV for version, --script vulners)
        nm.scan(hosts=host, arguments='-sV --script vulners')  
        scan_results[host] = nm[host]

    return scan_results

# Function to generate the result in JSON
def generate_json_report(scan_results, output_file):
    json_results = {}
    
    for host in scan_results:
        host_data = {}
        for proto in scan_results[host].all_protocols():
            ports = scan_results[host][proto].keys()
            proto_data = []
            for port in ports:
                port_data = {
                    "port": port,
                    "protocol": proto,
                    "service": scan_results[host][proto][port]['name'],
                    "state": scan_results[host][proto][port]['state'],
                    "product": scan_results[host][proto][port].get('product', 'Unknown'),
                    "version": scan_results[host][proto][port].get('version', 'Unknown'),
                    "vulnerabilities": scan_results[host][proto][port].get('script', {}).get('vulners', 'No vulnerabilities found')
                }
                proto_data.append(port_data)
            host_data[proto] = proto_data
        json_results[host] = host_data
    
    with open(output_file, 'w') as f:
        json.dump(json_results, f, indent=4)

# Main function
def main():
    # Step 0: Automatically detect network range
    print(Fore.RED + "Step 0: Automatically detecting network range")
    network_range = get_network_range()
    print(f"{Fore.RED}Detected network range: {network_range}")

    # Step 1: Discover active hosts
    print(Fore.RED + f"Step 1: Discovering active hosts on the network: {network_range}")
    active_hosts = discover_active_hosts(network_range)
    
    if not active_hosts:
        print(Fore.RED + "No active hosts found.")
        return
    
    # Step 2: Scan ports, services and vulnerabilities of active hosts
    print(Fore.RED + f"Step 2: Scanning active hosts: {active_hosts}")
    scan_results = scan_active_hosts(active_hosts)
    
    # Step 3: Generate the report in JSON
    json_output_file = "final_report.json"
    print(Fore.RED + f"Step 3: Generating report in JSON: {json_output_file}")
    generate_json_report(scan_results, json_output_file)

    # Step 4: Generate the report in HTML
    html_output_file = "final_report.html"
    print(Fore.RED + f"Step 4: Generating report in HTML: {html_output_file}")
    generate_html_report.generate_html_report(json_output_file, html_output_file)

if __name__ == "__main__":
    main()
