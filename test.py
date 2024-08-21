#this code is just in place to test the packet sniffing functionality

import pyshark

# Live capture on interface wlan1
capture = pyshark.LiveCapture(interface='wlan1')

for packet in capture.sniff_continuously(packet_count=5):
    print(packet)
