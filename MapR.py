import os
import sys
import nmap
import ipaddress
import pyfiglet

scan = nmap.PortScanner()

def main():

    if os.geteuid() != 0:
        print("[!] Running without root: -sS, -f, -O will throw errors or not work properly.\n[!] Consider running as root (sudo).\n")
        

    nameArt = pyfiglet.figlet_format("MapR.py")
    print(nameArt)
    print("- Made by RippR")


    print("\n")
    choices = [
        "1. Scan single IP address",
        "2. Scan a CIDR",
        "3. Exit"
    ]
    for choice in choices:
        print(choice)
    
    Options = int(input("\nWhat would you like to do? "))
    if Options < 1 or Options > 3:
        print("Invalid choice, try again.")
        sys.exit(1)

    Opts1(Options)

def Opts1(choice):
    if choice > 3 or choice < 1:
        print("Invalid choice, try again.")
        sys.exit(1)
    elif choice == 1:
        IPscanOpts()
    elif choice == 2:
        CIDRscanOpts()
    else:
        print("Exiting...")
        sys.exit(1)

def validIP(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validCIDR(cidr):
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False
    
def IPscanOpts():
    get_IP = input("\nWhat is the host to scan? (IP ADDR) ")
    if not validIP(get_IP):
        print("Improper IP address.")
        sys.exit(1)

    get_Timing = input("\nWhat timing (-T0 -> -T5)? ")

    get_ScanOpt = input("\nWhat Scan Option? (-sU, -sX, etc) ")
    if "-sI" in get_ScanOpt:
        get_Zombie = input("\nWhat zombie IP? ").strip()
        get_ScanOpt = get_ScanOpt.replace("-sI", f"-sI {get_Zombie}")

    # General Options
    get_If_Frag = input("\n Fragmented? (-f / -ff) ")
    get_Gen_Opts = input("\n General options? (-sV, -A, -O) ")

    scan_Host(get_IP, get_Timing, get_ScanOpt, get_If_Frag, get_Gen_Opts)

# Debugged lines 67-95 with chatGPT
def scan_Host(IP, Time, ScanOpts, GetFrag, GenOpts):
    Target = IP

    # Build options safely
    options = " ".join(opt for opt in [Time, ScanOpts, GetFrag, GenOpts] if opt)

    print(f"\nRunning: nmap {options} {Target}\n")

    scan.scan(Target, arguments=options)

    for host in scan.all_hosts():
        print(f"Host: {host}")
        print(f"State: {scan[host].state()}")

        for pro in scan[host].all_protocols():
            print(f"Protocol: {pro}")
            port_info = scan[host][pro]

            for port, state in port_info.items():
                service = ""

                if state.get("product"):
                    service = f"{state.get('product')} {state.get('version', '')}".strip()

                print(
                    f"Port: {port}\t"
                    f"State: {state['state']}\t"
                    f"Service: {service}"
                )

def CIDRscanOpts():
    get_CIDR = input("\nWhat is the CIDR to scan? (e.g. 10.10.10.0/24) ").strip()
    if not validCIDR(get_CIDR):
        print("Improper CIDR notation.")
        sys.exit(1)

    get_Timing = input("\nWhat timing (-T0 -> -T5)? ").strip()

    get_ScanOpt = input("\nWhat Scan Option? (-sS, -sU, etc) ").strip()

    if "-sI" in get_ScanOpt:
        get_Zombie = input("\nWhat zombie IP? ").strip()
        get_ScanOpt = get_ScanOpt.replace("-sI", f"-sI {get_Zombie}")

    get_If_Frag = input("\nFragmented? (-f / -ff) ").strip()
    get_Gen_Opts = input("\nGeneral options? (-sV, -A, -O) ").strip()

    scan_CIDR(get_CIDR, get_Timing, get_ScanOpt, get_If_Frag, get_Gen_Opts)

def scan_CIDR(CIDR, Time, ScanOpts, GetFrag, GenOpts):
    options = " ".join(opt for opt in [Time, ScanOpts, GetFrag, GenOpts] if opt)

    if os.geteuid() != 0:
        print("\n[!] CIDR scan running unprivileged — some hosts may be missed.\n")

    print(f"\nRunning: nmap {options} {CIDR}\n")

    scan.scan(hosts=CIDR, arguments=options)

    for host in scan.all_hosts():
        if scan[host].state() != "up":
            continue  # Skip down hosts

        print(f"\nHost: {host}")
        print(f"State: {scan[host].state()}")

        for pro in scan[host].all_protocols():
            print(f"Protocol: {pro}")
            port_info = scan[host][pro]

            for port, state in port_info.items():
                service = ""

                if state.get("product"):
                    service = f"{state.get('product')} {state.get('version', '')}".strip()

                print(
                    f"Port: {port}\t"
                    f"State: {state['state']}\t"
                    f"Service: {service}"
                )

                up_hosts = [h for h in scan.all_hosts() if scan[h].state() == "up"]

                print(f"\n[Bold]Scan Summary:[/Bold]")
                print(f"Hosts up: {len(up_hosts)}")
                print(f"Hosts scanned: {len(scan.all_hosts())}")
                
main()
