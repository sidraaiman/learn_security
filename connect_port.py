import socket

def scan_ip(ip):
    ports_to_check = [80, 443]  # Common web ports
    open_ports = []
    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def main():
    base_ip = "192.168.1."  # Change to your subnet base
    print("Scanning IPs from 192.168.1.1 to 192.168.1.5")
    for i in range(1, 6):
        ip = base_ip + str(i)
        open_ports = scan_ip(ip)
        if open_ports:
            print(f"{ip} has open ports: {open_ports}")
        else:
            print(f"{ip} has no open ports")

if __name__ == "__main__":
    main()
