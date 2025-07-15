from scapy.all import *
import subprocess
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Beacon, Dot11Elt
import csv 
import sys

log_file = open("log_medium.txt", "w")
sys.stdout = log_file
txop_results = []

interface = 'wlp65s0'
interface_monitor = 'wlp65s0mon'
freq_mhz = '5745'
bandwidth = '80MHz'

SIFS = 16
RTS_TA = None
RTS_RA = None   
RTS_TA_keep = None
RTS_RA_keep = None
RTS_TA_previous = 0
RTS_RA_previous = 0
RTS_nav_previous = 0
CTS_RA = None
CTS_RA_old = None
MT_CTS = None
MT_CTS_old = None
MT_RTS = None
MT_Data = None
MT_ACK = None
data_addr1 = None
data_addr2 = None
ACK_RA = None
nav_RTS = None
nav_CTS = None
nav_ACK = None
nav_CF = None
MT_CF = None
CF_RA = None
nav_BA = None
MT_BA = None
BA_RA = None
BA_TA = None
C_P = 1000
num_txop = 0
channel_util = 0
cu_class = None
CTS_nav_old = 0

# Set channel and bandwidth (VHT80)
subprocess.run(['airmon-ng', 'start', interface], check=True)
subprocess.run(['iw', 'dev', interface_monitor, 'set', 'freq', freq_mhz, bandwidth], check=True)


def S1(MT_ACK, MT_CF_END, MT_CTS):
    if MT_ACK:
        tx_op = MT_ACK - MT_CTS
        termination = MT_ACK
    elif MT_CF_END:
        tx_op = MT_CF_END - MT_CTS
        termination = MT_CF_END
    print("The termination of TXOP is", termination)
    return {"duration": tx_op, "termination_time": termination}

def S2(MT_RTS1, MT_CTS):
    tx_op = MT_RTS1 - MT_CTS
    print("The termination of TXOP is", MT_RTS1)
    return {"duration": tx_op, "termination_time": MT_RTS1}

def S3(MT_CTS1, MT_CTS):
    tx_op = MT_CTS1 - MT_CTS
    print("The termination of TXOP is", MT_CTS1)
    return {"duration": tx_op, "termination_time": MT_CTS1}

def nav_helper(nav_raw):
    nav_fixed = struct.unpack("<H", struct.pack(">H", nav_raw))[0]
    return nav_fixed

def extract_channel_utilization(packet):
    chu = 0
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else "<Hidden>"

        el = packet[Dot11Elt]
        while isinstance(el, Dot11Elt):
            if el.ID == 11:  # BSS Load Element
                bss_load_info = el.info
                if len(bss_load_info) >= 3:
                    station_count = int.from_bytes(bss_load_info[0:2], byteorder='little')
                    chu = bss_load_info[2]
                    print(f"[BEACON] SSID: {ssid} | Station Count: {station_count} | Channel Utilization: {chu}/255 ({(chu/ 255.0) * 100:.1f}%)")
                break
            el = el.payload.getlayer(Dot11Elt)

    return (chu / 255.0) * 100

# def classify_channel_utilization(channel_util):
#     ch_u_class = None
#     if channel_util <= 0.33:
#         ch_u_class = 'low channel utilization'
#     elif channel_util > 0.33 and channel_util<0.66:
#         ch_u_class = 'medium channel utilization'
#     else:
#         ch_u_class = 'high channel utilization'
#     return ch_u_class

def packet_callback(packet):
    global SIFS, RTS_TA, CTS_RA, MT_CTS, MT_RTS, data_addr2, ACK_RA, MT_Data, nav_RTS, data_addr1, \
        nav_CTS, nav_ACK, MT_ACK, C_P, MT_CTS_old, CTS_RA_old, num_txop, txop_results, RTS_RA, \
        RTS_TA_previous, RTS_RA_previous, RTS_TA_keep, RTS_RA_keep, MT_BA, nav_BA, nav_CF, MT_CF, \
        BA_RA, CF_RA, BA_TA, channel_util, cu_class, RTS_nav_previous, CTS_nav_old
    if packet.haslayer(Dot11):
        dot11 = packet[Dot11]
        
        rt = packet.getlayer(RadioTap)
        mac_ts = getattr(rt, 'timestamp', None)


        # RTS frame: Type 1 (Control), Subtype 11
        if dot11.type == 1 and dot11.subtype == 11:
            RTS_TA = dot11.addr2
            RTS_RA = dot11.addr1
            RTS_TA_keep = RTS_TA
            RTS_RA_keep = RTS_RA
            print(f"[RTS] RA: {dot11.addr1}, TA: {dot11.addr2} | {packet.time}")
            print(f"[RTS] MAC time: {mac_ts} μs | TA={dot11.addr2}, RA={dot11.addr1}")
            nav_RTS = nav_helper(dot11.ID)  # Duration value (NAV) in microseconds
            print(f"[RTS] NAV time: {nav_RTS} μs")
            MT_RTS = mac_ts
            C_P = 1
        

        # CTS frame: Type 1 (Control), Subtype 12
        elif dot11.type == 1 and dot11.subtype == 12:
            if C_P == 2:
                CTS_RA_old = CTS_RA
                MT_CTS_old = MT_CTS
                CTS_nav_old = nav_CTS
            CTS_RA = dot11.addr1
            print(f"[CTS] RA: {dot11.addr1} | {packet.time}")
            print(f"[CTS] MAC time: {mac_ts} μs | RA={dot11.addr1}")
            nav_CTS = nav_helper(dot11.ID)  # Duration value (NAV) in microseconds
            print(f"[CTS] NAV time: {nav_CTS} μs")
            MT_CTS = mac_ts
            C_P = 2

        # ACK frames: type 1 (Control), subtype 13
        elif dot11.type == 1 and dot11.subtype == 13:
            ACK_RA = dot11.addr1  # destination of the ACK
            print(f"[ACK] MAC time: {mac_ts} μs | RA: {dot11.addr1}")
            nav_ACK = nav_helper(dot11.ID)
            print(f"[ACK] NAV time: {nav_ACK} μs")
            MT_ACK = mac_ts
            C_P = 3

        # CF End
        elif dot11.type == 1 and dot11.subtype == 14:
            CF_RA = dot11.addr1  # destination of the ACK
            print(f"[CF_END] MAC time: {mac_ts} μs | RA: {dot11.addr1}")
            nav_CF = nav_helper(dot11.ID)
            print(f"[CF_END] NAV time: {nav_CF} μs")
            MT_CF = mac_ts
            C_P = 5

        # Block Ack
        elif dot11.type == 1 and dot11.subtype == 9:
            BA_RA = dot11.addr1  # destination of the ACK
            BA_TA = dot11.addr2
            print(f"[BA] MAC time: {mac_ts} μs | RA: {dot11.addr1}, TA: {dot11.addr2}")
            nav_BA = nav_helper(dot11.ID)
            print(f"[BA] NAV time: {nav_BA} μs")
            MT_BA = mac_ts
            C_P = 6

        # Beacon frame
        elif dot11.type == 0 and dot11.subtype == 8:
            print(f"[BEACON] from {dot11.addr2}")
            channel_util = extract_channel_utilization(packet)
            # if channel_util is not None:
            #     cu_class = classify_channel_utilization(channel_util)
            
        # Data frames: type=2, subtype between 0 and 15
        elif dot11.type == 2:
            data_addr2 = dot11.addr2
            data_addr1 = dot11.addr1
            MT_Data = mac_ts
            print(f"[DATA] MAC time: {mac_ts} μs | src: {dot11.addr2} | des: {dot11.addr1}")
            C_P = 4 

        else:
            print("no RTS/CTS/DATA/ACK packet captured")
            C_P = 1000 
            


        # From Request TXOP to Within TXOP
        if RTS_TA is not None and CTS_RA is not None and C_P <= 2: 
            if RTS_TA == CTS_RA and MT_CTS - MT_RTS >= 30 and MT_CTS - MT_RTS <= 75:
                RTS_RA_previous = RTS_RA
                RTS_TA_previous = RTS_TA
                RTS_nav_previous = nav_RTS
                print("RTS_TA equals CTS_RA")
                print("Going from Request TXOP state to Within TXOP state")

            elif C_P == 1:
                print("RTS_TA does NOT equal CTS_RA")
                s2 = S2(MT_RTS, MT_CTS)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s2,
                    "From": RTS_TA_previous,
                    "To": RTS_RA_previous, 
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "Another RTS",
                    "Announced duration": nav_CTS,
                    "RTS nav": RTS_nav_previous
                })
                print("*******************")
                print("TX OP in S2 is ",  s2["duration"])
                print("Going from Within TXOP state to Request TXOP state")
                CTS_RA = None
                MT_CTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None        

        # Within TXOP:
        if C_P >= 2 and CTS_RA is not None:
            if MT_CTS_old is not None and CTS_RA != CTS_RA_old:
                print("here 1")
                s3 = S3(MT_CTS, MT_CTS_old)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s3,
                    "From": CTS_RA_old,
                    "To": "Unknown", 
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "Previous CTS",
                    "Terminated by": "New CTS",
                    "Announced duration": CTS_nav_old,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in Within TXOP state is", s3["duration"])
                RTS_TA = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None 
                nav_BA = None
                MT_BA = None
                BA_RA = None 

            elif data_addr2 != CTS_RA and C_P == 4 and MT_Data is not None and MT_Data - MT_CTS >= nav_CTS:
                print("here2")
                s3 = S3(MT_Data, MT_CTS)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s3,
                    "From": CTS_RA,
                    "To": "Unknown" if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "Another Data",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in Within TXOP state is", s3["duration"])
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                ACK_RA = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None 
                nav_BA = None
                MT_BA = None
                BA_RA = None   

            elif ACK_RA != CTS_RA and C_P == 3 and MT_ACK is not None and MT_ACK - MT_CTS >= nav_CTS:
                print("here3")
                s3 = S3(MT_ACK, MT_CTS)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s3,
                    "From": CTS_RA,
                    "To": "Unknown" if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "Another ACK",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in Within TXOP state is", s3["duration"])
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None 
                nav_BA = None
                MT_BA = None
                BA_RA = None 

            elif BA_RA != CTS_RA and C_P == 6 and MT_BA is not None and MT_BA - MT_CTS >= nav_CTS:
                print("here11")
                s3 = S3(MT_BA, MT_CTS)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s3,
                    "From": CTS_RA,
                    "To": "Unknown" if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "Another BA",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in Within TXOP state is", s3["duration"])
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None

            elif MT_Data is not None:
                print("here4")
                if (data_addr2 == CTS_RA and MT_Data - MT_CTS <= nav_CTS):
                    print("Stay in Within TXOP state again")
            elif (ACK_RA == CTS_RA and nav_ACK is not None and nav_ACK >= SIFS):
                print("here5")
                print("Stay in Within TXOP state again")
            elif (BA_RA == CTS_RA and nav_BA is not None and nav_BA >= SIFS):
                print("here6")
                print("Stay in Within TXOP state again")

        # From Within TXOP to TXOP End
        if (ACK_RA is not None or BA_RA is not None or CF_RA is not None) and (CTS_RA is not None or data_addr2 is not None):
            if ACK_RA == CTS_RA and MT_CTS is not None and MT_ACK is not None and nav_ACK <= SIFS and MT_CTS < MT_ACK:
                print("END here1")
                print("Going from Within TXOP state to TXOP End state")
                s1 = S1(MT_ACK, None, MT_CTS)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s1,
                    "From": ACK_RA,
                    "To": "Unknown" if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "yes",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "Final ACK",
                    "Announced duration":nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in TXOP End state is", s1["duration"]) 
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None

            elif CF_RA is not None and CTS_RA is not None and nav_CF <= SIFS and MT_CTS < MT_CF:
                print("END here10")
                print("Going from Within TXOP state to TXOP End state")
                s1 = S1(MT_CF, None, MT_CTS)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s1,
                    "From": CTS_RA,
                    "To": "Unknown" if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "yes",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "CF-END",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in TXOP End state is", s1["duration"]) 
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None

            elif BA_RA == CTS_RA and MT_CTS is not None and MT_BA is not None and nav_BA <= SIFS and MT_CTS < MT_BA:
                print("END here20")
                print("Going from Within TXOP state to TXOP End state")
                s1 = S1(MT_BA, None, MT_CTS)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s1,
                    "From": BA_RA,
                    "To": "Unknown"if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "yes",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "Final BA",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in TXOP End state is", s1["duration"]) 
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None

            elif ACK_RA != CTS_RA and MT_ACK is not None and nav_ACK <= SIFS and C_P == 2:
                print("END here2")
                s3 = S3(MT_CTS, MT_ACK)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s3,
                    "From": ACK_RA,
                    "To": "Unknown" if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "CTS",
                    "Terminated by": "Another BA",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in TXOP End state is", s3["duration"])
                RTS_TA = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None

            elif ACK_RA == data_addr2 and MT_ACK is not None and nav_ACK <= SIFS and C_P == 3 and MT_Data is not None:
                print("END here3")
                s3 = S3(MT_ACK, MT_Data)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s3,
                    "From": data_addr2,
                    "To": data_addr1 if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "Data",
                    "Terminated by": "ACK",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in TXOP End state is", s3["duration"])
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None

            elif BA_RA == data_addr2 and MT_BA is not None and nav_BA <= SIFS and C_P == 6 and MT_Data is not None:
                print("END here30")
                s3 = S3(MT_BA, MT_Data)
                num_txop += 1
                txop_results.append({
                    "txop_num": num_txop,
                    **s3,
                    "From": data_addr2,
                    "To": data_addr1 if (RTS_TA is None or RTS_TA != CTS_RA) else RTS_RA,
                    "Ended Properly": "no",
                    "Channel Utilization": channel_util,
                    "TXOPs based on": "Data",
                    "Terminated by": "BA",
                    "Announced duration": nav_CTS,
                    "RTS nav": nav_RTS
                })
                print("*********************************")
                print("TX OP in TXOP End state is", s3["duration"])
                RTS_TA = None
                CTS_RA = None
                MT_CTS = None
                MT_RTS = None
                data_addr2 = None
                ACK_RA = None
                MT_Data = None
                nav_RTS = None
                nav_CTS = None
                nav_ACK = None
                MT_ACK = None
                MT_CTS_old = None
                CTS_RA_old = None
                nav_CF = None
                MT_CF = None
                CF_RA = None
                nav_BA = None
                MT_BA = None
                BA_RA = None

    print("The number of TXOP is", num_txop)
    print(" ")
    return 

sniff(iface=interface_monitor, prn=packet_callback, timeout=600)

sys.stdout = sys.__stdout__
log_file.close()
print("Sniffing done. Output saved to txop_log_output.txt")

# Saving results to a csv
with open("txop_results_medium.csv", "w", newline="") as csvfile:
    fieldnames = ["txop_num", "duration", "termination_time", "From", "To","Ended Properly", "Channel Utilization", "TXOPs based on", "Terminated by", \
                  "Announced duration", "RTS nav"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerows(txop_results)

print("Saved TXOP results to txop_results.csv")
subprocess.run(['airmon-ng', 'stop', interface_monitor], check=True)

