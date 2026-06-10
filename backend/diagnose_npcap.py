import os
import sys

try:
    from scapy.config import conf
    conf.use_npcap = True
    
    from scapy.all import get_if_list
    
    print("--- SCAPY CONFIGURATION ---")
    print(f"conf.use_pcap: {getattr(conf, 'use_pcap', 'Not Set')}")
    print(f"conf.use_npcap: {getattr(conf, 'use_npcap', 'Not Set')}")
    print(f"conf.libpcap: {getattr(conf, 'libpcap', 'Not Set')}")
    print(f"conf.libpcap_version: {getattr(conf, 'libpcap_version', 'Not Set')}")
    
    print("\n--- DLL CHECKS ---")
    sys32 = r"C:\Windows\System32"
    npcap_dir = r"C:\Windows\System32\Npcap"
    print(f"wpcap.dll in System32: {os.path.exists(os.path.join(sys32, 'wpcap.dll'))}")
    print(f"wpcap.dll in Npcap dir: {os.path.exists(os.path.join(npcap_dir, 'wpcap.dll'))}")
    print(f"npcap.sys in drivers: {os.path.exists(os.path.join(sys32, 'drivers', 'npcap.sys'))}")
    
    print("\n--- NETWORK INTERFACES ---")
    print(get_if_list())
except Exception as e:
    print(f"Error during diagnosis: {e}")
