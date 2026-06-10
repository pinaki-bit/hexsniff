from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import json

print("=== Windows Interfaces ===")
ifaces = get_windows_if_list()
for i in ifaces:
    name = i.get('name', '')
    desc = i.get('description', '')
    guid = i.get('guid', '')
    ips = i.get('ips', [])
    if 'Wi-Fi' in name or 'Wireless' in desc or 'MediaTek' in desc:
        print(f"  Name: {name}")
        print(f"  Desc: {desc}")
        print(f"  GUID: {guid}")
        print(f"  IPs: {ips}")
        print()

print("=== get_if_list() ===")
for iface in get_if_list():
    print(f"  {iface}")

print("\n=== conf.ifaces ===")
for key, iface in conf.ifaces.items():
    name = getattr(iface, 'name', str(key))
    desc = getattr(iface, 'description', '')
    guid = getattr(iface, 'guid', '')
    ip = getattr(iface, 'ip', '')
    if 'Wi-Fi' in name or 'Wireless' in desc or 'MediaTek' in desc:
        print(f"  Key: {key}")
        print(f"  Name: {name}")
        print(f"  Desc: {desc}")
        print(f"  GUID: {guid}")
        print(f"  IP: {ip}")
        print()

print("\n=== Testing sniff on each wireless iface ===")
for i in ifaces:
    name = i.get('name', '')
    desc = i.get('description', '')
    guid = i.get('guid', '')
    ips = i.get('ips', [])
    if 'Wi-Fi' in name or 'Wireless' in desc:
        # Try sniffing with the friendly name
        for test_name in [name, f"\\\\Device\\\\NPF_{{{guid}}}" if guid else None]:
            if not test_name:
                continue
            try:
                pkts = sniff(iface=test_name, count=2, timeout=3)
                print(f"  SNIFF OK on '{test_name}' -> {len(pkts)} packets captured")
            except Exception as e:
                print(f"  SNIFF FAILED on '{test_name}' -> {e}")
