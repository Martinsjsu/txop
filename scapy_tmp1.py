
from scapy.all import *
import subprocess

channel = '161'
interface = 'wlp34s0mon'

# Set the channel before sniffing
subprocess.run(['iw', 'dev', interface, 'set', 'channel', channel], check=True)

def packet_callback(packet):
    print(packet.summary())

sniff(iface=interface, prn=packet_callback, count=10) 