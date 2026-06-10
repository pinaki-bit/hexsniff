import socket
from scapy.all import sniff, conf

print("Testing L3 sniffing...")
try:
    conf.L3socket
    print("conf.L3socket is available.")
    
    # Try to sniff a few packets using L3 socket (requires admin, but maybe it works?)
    # On Windows, raw sockets need to be bound to a specific IP
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    print(f"Binding to IP: {ip}")
    
    def pkt_handler(pkt):
        print(pkt.summary())

    # L3rawSocket might work if we set conf.L3socket
    sniff(count=2, prn=pkt_handler, timeout=5)
    print("Successfully sniffed via default!")
except Exception as e:
    print(f"Failed L3 sniffing: {e}")

try:
    import os
    print("Raw socket test:")
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((socket.gethostbyname(socket.gethostname()), 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print("Raw socket bound and promiscuous mode enabled!")
    data, addr = s.recvfrom(65565)
    print("Captured raw packet!")
except Exception as e:
    print(f"Raw socket failed: {e}")
