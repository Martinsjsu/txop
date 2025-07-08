import pyshark

capture = pyshark.LiveCapture(interface='wlp34s0mon')

for packet in capture.sniff_continuously():
    print(packet)