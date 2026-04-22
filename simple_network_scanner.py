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
    print("\n=== service explanations ===")

    explanations = {
        21: "FTP - file transfer (can be insecure)",
        22: "SSH - remote admin access",
        23: "Telnet - insecure remote access",
        80: "HTTP - web traffic (unencrypted)",
        443: "HTTPS - secure web traffic",
        445: "SMB - file sharing (ransomware target)",
        3389: "RDP - remote desktop (high risk)"
    }

    for port in open_ports:
        print(f"port {port}: {explanations.get(port, 'unknown service')}")

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
        print("ssh exposed - secure but should be restricted")
        return

    print("overall risk: LOW")
    print("minimal exposure detected")

def main():
    print("simple banking network scanner\n")

    target = input("enter target ip: ")

    if not is_reachable(target):
        return

    open_ports = scan_ports(target)

    if open_ports:
        explain_ports(open_ports)

    analyze_risk(open_ports)

    print(f"\ntotal open ports: {len(open_ports)}")

if __name__ == "__main__":
    main()
