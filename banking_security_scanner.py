import socket

COMMON_PORTS = [21, 22, 23, 80, 443, 445, 3389]

def is_reachable(target):
    try:
        socket.gethostbyname(target)
        print(f"{target} reachable")
        return True
    except:
        print("target unreachable")
        return False

def scan_ports(target):
    open_ports = []

    print(f"\nscanning {target}...\n")

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"port {port} is OPEN")
            open_ports.append(port)
        else:
            print(f"port {port} is closed")

        sock.close()

    return open_ports

def explain_ports(open_ports):
    print("\n=== SERVICE EXPLANATIONS ===")

    explanations = {
        21: "FTP - file transfer (insecure)",
        22: "SSH - remote admin access",
        23: "Telnet - insecure remote access",
        80: "HTTP - unencrypted web traffic",
        443: "HTTPS - secure web traffic",
        445: "SMB - file sharing (ransomware target)",
        3389: "RDP - remote desktop (high risk)"
    }

    for port in open_ports:
        print(f"port {port}: {explanations.get(port, 'unknown service')}")

def detect_attack_patterns(open_ports):
    print("\n=== THREAT DETECTION ===")

    if 445 in open_ports:
        print("[!] Possible Ransomware Entry Point (SMB exposed)")

    if 3389 in open_ports:
        print("[!] RDP exposed → Brute-force risk")

    if 22 in open_ports and 3389 in open_ports:
        print("[!] Multiple remote access services → Admin exposure risk")

    if len(open_ports) >= 3:
        print("[!] Multiple services open → Increased attack surface")

    if not open_ports:
        print("[+] No obvious attack vectors detected")

def analyze_risk(open_ports):
    print("\n=== BANKING SYSTEM RISK ANALYSIS ===")

    if not open_ports:
        print("overall risk: LOW")
        print("no exposed services - system appears secure")
        return

    if 445 in open_ports or 3389 in open_ports:
        print("overall risk: HIGH")
        print("critical: SMB or RDP exposed - high risk for bank systems")
        return

    if 22 in open_ports:
        print("overall risk: MEDIUM")
        print("ssh exposed - should be restricted")
        return

    print("overall risk: LOW")
    print("minimal exposure detected")

def recommend_fixes(open_ports):
    print("\n=== SECURITY RECOMMENDATIONS ===")

    if 445 in open_ports:
        print("- Disable SMB or restrict via firewall")

    if 3389 in open_ports:
        print("- Restrict RDP using VPN or IP whitelist")

    if 22 in open_ports:
        print("- Use SSH keys and disable password login")

    if not open_ports:
        print("- No immediate action required")

    print("- Enable firewall rules")
    print("- Use intrusion detection systems")

def incident_response_mode(open_ports):
    print("\n=== INCIDENT RESPONSE SIMULATION ===")

    if 445 in open_ports:
        print("ACTION: Isolate system immediately (ransomware risk)")

    elif 3389 in open_ports:
        print("ACTION: Monitor logs and block suspicious IPs")

    elif open_ports:
        print("ACTION: Investigate exposed services")

    else:
        print("ACTION: Continue monitoring system")

def main():
    print("=== BANKING SECURITY ASSESSMENT TOOL ===\n")

    target = input("enter target ip: ")

    if not is_reachable(target):
        return

    open_ports = scan_ports(target)

    if open_ports:
        explain_ports(open_ports)

    detect_attack_patterns(open_ports)
    analyze_risk(open_ports)
    recommend_fixes(open_ports)
    incident_response_mode(open_ports)

    print(f"\ntotal open ports: {len(open_ports)}")

if __name__ == "__main__":
    main()
