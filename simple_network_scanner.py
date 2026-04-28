import socket
import sys

COMMON_PORTS = [21, 22, 23, 80, 443, 445, 3389]

PORT_MEANINGS = {
    21: "FTP – File transfer (can expose sensitive data)",
    22: "SSH – Remote access (secure but risky if exposed)",
    23: "Telnet – Insecure remote access",
    80: "HTTP – Web traffic (not encrypted)",
    443: "HTTPS – Secure web traffic",
    445: "SMB – File sharing (common ransomware target)",
    3389: "RDP – Remote desktop (HIGH RISK if open)"
}

def scan_ports(target):
    open_ports = []

    print(f"\n[+] Scanning {target}...\n")

    try:
        target_ip = socket.gethostbyname(target)
    except:
        print("Invalid target")
        return []

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            open_ports.append(port)
            print(f"Port {port} OPEN → {PORT_MEANINGS.get(port, 'Unknown service')}")

        sock.close()

    return open_ports


def analyze_risk(open_ports):
    risk_level = "LOW"
    reason = "Minimal exposure"

    if 22 in open_ports and 3389 in open_ports:
        risk_level = "CRITICAL"
        reason = "Multiple remote admin services exposed (SSH + RDP)"

    elif 445 in open_ports:
        risk_level = "HIGH"
        reason = "SMB exposed – common ransomware attack vector"

    elif 80 in open_ports or 443 in open_ports:
        risk_level = "MEDIUM"
        reason = "Web services exposed to the internet"

    print("\n=== BANKING SYSTEM RISK ANALYSIS ===")
    print(f"Overall Risk Level: {risk_level}")
    print(f"Reason: {reason}")

    return risk_level, reason


def save_report(target, open_ports, risk_level, reason):
    with open("scan_report.txt", "w") as f:
        f.write("=== SCAN REPORT ===\n")
        f.write(f"Target: {target}\n\n")

        for port in open_ports:
            f.write(f"Port {port} OPEN → {PORT_MEANINGS.get(port, 'Unknown')}\n")

        f.write("\n=== RISK ANALYSIS ===\n")
        f.write(f"Risk Level: {risk_level}\n")
        f.write(f"Reason: {reason}\n")


if __name__ == "__main__":
    target = input("Enter target (IP or domain): ")

    open_ports = scan_ports(target)

    if not open_ports:
        print("\nNo open ports found or invalid target.")
        sys.exit()

    risk_level, reason = analyze_risk(open_ports)

    save_report(target, open_ports, risk_level, reason)

    print("\nReport saved as scan_report.txt")
