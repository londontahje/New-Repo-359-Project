import socket

def ping_host(target):
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


def scan_common_ports(target):
    common_ports = [21, 22, 23, 80, 443, 445, 3389]
    open_ports = []

    print(f"\nscanning {target}...\n")

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"port {port} is open")
            open_ports.append(port)
        else:
            print(f"port {port} is closed")

        sock.close()

    return open_ports


def ai_risk_analysis(open_ports):
    print("\n=== ai scanner risk analysis ===\n")

    findings = []
    risk = "low"

    if 23 in open_ports:
        findings.append("telnet is open (no encryption)")
        risk = "critical"

    if 445 in open_ports:
        findings.append("smb is open (common attack target)")
        if risk != "critical":
            risk = "high"

    if 3389 in open_ports:
        findings.append("rdp is open (remote access risk)")
        if risk != "critical":
            risk = "high"

    if 21 in open_ports:
        findings.append("ftp is open (plaintext credentials)")
        if risk != "critical":
            risk = "high"

    if 80 in open_ports and 443 not in open_ports:
        findings.append("http without https (no encryption)")
        if risk == "low":
            risk = "medium"

    if len([p for p in open_ports if p in [22, 23, 3389]]) >= 2:
        findings.append("multiple remote access ports open")
        risk = "critical"

    print(f"overall risk: {risk.upper()}\n")

    if findings:
        for f in findings:
            print(f"- {f}")
    else:
        print("no major risks found")


def main():
    print("simple ai network scanner\n")

    target = input("enter target ip: ").strip()

    if not target:
        print("no target entered")
        return

    if ping_host(target):
        print(f"{target} reachable")
        ports = scan_common_ports(target)
        ai_risk_analysis(ports)
    else:
        print("target unreachable")


if __name__ == "__main__":
    main()
