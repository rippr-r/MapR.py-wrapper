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
    
    try:
        Options = int(input("\nWhat would you like to do? "))
        if Options < 1 or Options > 3:
            print("Please enter a number between 1 and 3.")
            sys.exit(1)
    except ValueError:
        print("Please enter a number between 1 and 3.")
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
        sys.exit(0)

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

def validScanOpts(scan_opts):
    valid_opts = {
        "-sS","-sT","-sA","-sW","-sM",
        "-sU","-sN","-sF","-sX","-sI",
        "-sY","-sZ","-sO","-b"
    }

    # Handle -sI with zombie IP separately
    tokens = scan_opts.split()
    i = 0
    while i < len(tokens):
        if tokens[i] == "-sI":
            i += 2  # Skip the zombie IP
            continue
        if tokens[i] not in valid_opts:
            return False
        i += 1
    return True

def validTiming(set_timing):
    valid_timings = [
        "-T0", "-T1", "-T2",
        "-T3", "-T4", "-T5"
    ]
    
    # Reject if input contains spaces (multiple timings)
    if " " in set_timing:
        return False
    return set_timing in valid_timings

def validFragmentation(set_frag):
    valid_frags = ["-f", "-ff"]
    return set_frag in valid_frags

def validGeneralOpts(gen_opts):
    valid_opts = [
        "-sV", "-O", "-6", "-A",
        "-sn", "-Pn", "-PS", "-PA",
        "-PU", "-PY", "-PE", "-PP",
        "-PM", "-F", "-r"
    ]

    for opt in gen_opts.split():
        if opt not in valid_opts:
            return False
    return True

def IPscanOpts():
    get_IP = input("\nWhat is the host to scan? (IP ADDR) ")
    if not validIP(get_IP):
        print("Improper IP address.")
        sys.exit(1)

    get_Timing = input("\nWhat timing (-T0 -> -T5)? ")
    if get_Timing and not validTiming(get_Timing):
        print("Improper timing option.")
        sys.exit(1)
    
    get_ScanOpt = input("\nWhat Scan Option? (-sU, -sX, etc) ")
    if get_ScanOpt and not validScanOpts(get_ScanOpt):
        print("Improper scan option.")
        sys.exit(1)
    if "-sI" in get_ScanOpt:
        get_Zombie = input("\nWhat zombie IP? ").strip()
        if not validIP(get_Zombie):
            print("Improper zombie IP address.")
            sys.exit(1)
        get_ScanOpt = get_ScanOpt.replace("-sI", f"-sI {get_Zombie}")

    # General Options
    get_If_Frag = input("\n Fragmented? (-f / -ff) ")
    if get_If_Frag and not validFragmentation(get_If_Frag):
        print("Improper fragmentation option.")
        sys.exit(1)
    get_Gen_Opts = input("\n General options? (-sV, -A, -O) ")
    if get_Gen_Opts and not validGeneralOpts(get_Gen_Opts):
        print("Improper general options.")
        sys.exit(1)

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
    if get_Timing and not validTiming(get_Timing):
        print("Improper timing option.")
        sys.exit(1)
    get_ScanOpt = input("\nWhat Scan Option? (-sS, -sU, etc) ").strip()
    if get_ScanOpt and not validScanOpts(get_ScanOpt):
        print("Improper scan option.")
        sys.exit(1)
    if "-sI" in get_ScanOpt:
        get_Zombie = input("\nWhat zombie IP? ").strip()
        get_ScanOpt = get_ScanOpt.replace("-sI", f"-sI {get_Zombie}")

    get_If_Frag = input("\nFragmented? (-f / -ff) ").strip()
    if get_If_Frag and not validFragmentation(get_If_Frag):
        print("Improper fragmentation option.")
        sys.exit(1)

    get_Gen_Opts = input("\nGeneral options? (-sV, -A, -O) ").strip()
    if get_Gen_Opts and not validGeneralOpts(get_Gen_Opts):
        print("Improper general options.")
        sys.exit(1)

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

    print(f"\nScan Summary:")
    print(f"Hosts up: {len(up_hosts)}")
    print(f"Hosts scanned: {len(scan.all_hosts())}")
                
if __name__ == "__main__":
    main()
