from scapy.all import *
import subprocess

from scapy.layers.dot11 import Dot11

channel = '161'
interface = 'wlp34s0mon'

# Set the channel before sniffing
subprocess.run(['iw', 'dev', interface, 'set', 'channel', channel], check=True)

def packet_callback(packet):
    if packet.haslayer(Dot11) and packet.type == 1:
        print(f"{packet.summary()} | {packet.time}")

sniff(iface=interface, prn=packet_callback, timeout=10)
