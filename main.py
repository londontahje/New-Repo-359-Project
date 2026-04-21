import socket

COMMON_PORTS = [21, 22, 23, 80, 443, 445, 3389]

def scan_ports(target):
    open_ports = []

    print("\n[+] Scanning:", target)

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"[OPEN] Port {port}")
            open_ports.append(port)
        else:
            print(f"[CLOSED] Port {port}")

        sock.close()

    return open_ports


def explain_ports(open_ports):
    print("\n[+] Port Explanations:")

    explanations = {
        21: "FTP - File transfer, can be insecure if anonymous login allowed",
        22: "SSH - Remote login, secure but risky if exposed",
        23: "Telnet - Insecure remote access (plaintext)",
        80: "HTTP - Web traffic, unencrypted",
        443: "HTTPS - Secure web traffic",
        445: "SMB - File sharing, often targeted in attacks",
        3389: "RDP - Remote desktop, high risk if exposed"
    }

    for port in open_ports:
        print(f"Port {port}: {explanations.get(port, 'Unknown service')}")


def main():
    target = input("Enter target IP: ")

    open_ports = scan_ports(target)

    if open_ports:
        explain_ports(open_ports)
    else:
        print("\n[-] No open ports found.")


if __name__ == "__main__":
    main()
