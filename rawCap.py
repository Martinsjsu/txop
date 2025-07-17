from scapy.all import *


interface = 'wlp65s0'
interface_monitor = 'wlp65s0mon'
freq_mhz = '5805'
bandwidth = '80MHz'
saved_file = "intel_wifi6.pcap"

# Set channel and bandwidth 
subprocess.run(['airmon-ng', 'start', interface], check=True)
subprocess.run(['iw', 'dev', interface_monitor, 'set', 'freq', freq_mhz, bandwidth], check=True)


print("Starting raw capture!")
packets = sniff(iface=interface_monitor, timeout=600)

wrpcap(saved_file, packets)
print("Raw capture finished. Data saved to", saved_file)
subprocess.run(['airmon-ng', 'stop', interface_monitor], check=True)


# Off line analysis
