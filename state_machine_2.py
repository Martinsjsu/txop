from scapy.all import *
import subprocess
from scapy.layers.dot11 import Dot11, RadioTap
import csv 
import sys

log_file = open("log.txt", "w")
sys.stdout = log_file
txop_results = []

interface = 'wlp34s0mon'
freq_mhz = '5805'
bandwidth = '80MHz'

SIFS = 16
RTS_TA = None
RTS_RA = None
CTS_RA = None
MT_CTS = None
MT_CTS_old = None
CTS_RA_old = None
MT_RTS = None
data_addr1 = None
data_addr2 = None
ACK_RA = None
MT_Data = None
nav_RTS = None
nav_CTS = None
nav_ACK = None
MT_ACK = None
C_P = 1000
num_txop = 0
RTS_TA_previous = 0
RTS_RA_previous = 0

# Set channel and bandwidth (VHT80)
subprocess.run(['iw', 'dev', interface, 'set', 'freq', freq_mhz, bandwidth], check=True)

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

def packet_callback(packet):
    global SIFS, RTS_TA, CTS_RA, MT_CTS, MT_RTS, data_addr2, ACK_RA, MT_Data, nav_RTS, data_addr1, \
        nav_CTS, nav_ACK, MT_ACK, C_P, MT_CTS_old, CTS_RA_old, num_txop, txop_results, RTS_RA, \
        RTS_TA_previous, RTS_RA_previous
    if packet.haslayer(Dot11):
        dot11 = packet[Dot11]
        
        rt = packet.getlayer(RadioTap)
        mac_ts = getattr(rt, 'mac_timestamp', None)


        # RTS frame: Type 1 (Control), Subtype 11
        if dot11.type == 1 and dot11.subtype == 11:
            RTS_TA = dot11.addr2
            RTS_RA = dot11.addr1
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
            if RTS_TA == CTS_RA and MT_CTS - MT_RTS >= 40 and MT_CTS - MT_RTS <= 60:
                RTS_RA_previous = RTS_RA
                RTS_TA_previous = RTS_TA
                print("RTS_TA equals CTS_RA")
                print("Going from Request TXOP state to Within TXOP state")

            elif C_P == 1:
                print("RTS_TA does NOT equal CTS_RA")
                s2 = S2(MT_RTS, MT_CTS)
                num_txop += 1
                print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                txop_results.append({
                    "txop_num": num_txop,
                    **s2,
                    "From": RTS_TA_previous,
                    "To": RTS_RA_previous, 
                    "Ended Properly": "no"
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
                    "To": "Unkown", 
                    "Ended Properly": "no"
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
            elif data_addr2 != CTS_RA and C_P == 4 and MT_Data - MT_CTS >= nav_CTS:
                print("here2")
                s3 = S3(MT_Data, MT_CTS)
                num_txop += 1
                if RTS_TA is None or RTS_TA != CTS_RA: 
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": data_addr2,
                        "To": data_addr1,
                        "Ended Properly": "no"
                    })
                else:
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": data_addr2,
                        "To": data_addr1,
                        "Ended Properly": "no"
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
            elif ACK_RA != CTS_RA and C_P == 3 and MT_ACK - MT_CTS >= nav_CTS:
                print("here3")
                s3 = S3(MT_ACK, MT_CTS)
                num_txop += 1
                if RTS_TA is None or RTS_TA != CTS_RA: 
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": ACK_RA,
                        "To": "Unkown",
                        "Ended Properly": "no"
                    })
                else:
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": RTS_TA,
                        "To": RTS_RA,
                        "Ended Properly": "no"
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
            elif MT_Data is not None:
                print("here4")
                if (data_addr2 == CTS_RA and MT_Data - MT_CTS <= nav_CTS):
                    print("Stay in Within TXOP state again")
            elif (ACK_RA == CTS_RA and nav_ACK is not None and nav_ACK >= SIFS):
                print("here5")
                print("Stay in Within TXOP state again")

        # From Within TXOP to TXOP End
        if ACK_RA is not None and (CTS_RA is not None or data_addr2 is not None):
            if ACK_RA == CTS_RA and (MT_ACK-MT_CTS <= nav_CTS) and nav_ACK <= SIFS and MT_CTS < MT_ACK:
                print("END here1")
                print("Going from Within TXOP state to TXOP End state")
                s1 = S1(MT_ACK, None, MT_CTS)
                num_txop += 1
                if RTS_TA is None or RTS_TA != CTS_RA: 
                    txop_results.append({
                        "txop_num": num_txop,
                        **s1,
                        "From": data_addr2,
                        "To": data_addr1,
                        "Ended Properly": "yes"
                    })
                else:
                    txop_results.append({
                        "txop_num": num_txop,
                        **s1,
                        "From": RTS_TA,
                        "To": RTS_RA,
                        "Ended Properly": "yes"
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
            elif ACK_RA != CTS_RA and nav_ACK <= SIFS and C_P == 2:
                print("END here2")
                s3 = S3(MT_CTS, MT_ACK)
                num_txop += 1
                if RTS_TA is None or RTS_TA != CTS_RA: 
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": ACK_RA,
                        "To": "Unkown",
                        "Ended Properly": "yes"
                    })
                else:
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": RTS_TA,
                        "To": RTS_RA,
                        "Ended Properly": "yes"
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
            elif ACK_RA == data_addr2 and nav_ACK <= SIFS and C_P == 3 and MT_Data is not None:
                print("END here3")
                s3 = S3(MT_ACK, MT_Data)
                num_txop += 1
                if RTS_TA is None or RTS_TA != CTS_RA: 
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": data_addr2,
                        "To": data_addr1,
                        "Ended Properly": "yes"
                    })
                else:
                    txop_results.append({
                        "txop_num": num_txop,
                        **s3,
                        "From": RTS_TA,
                        "To": RTS_RA,
                        "Ended Properly": "yes"
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
    print("The number of TXOP is", num_txop)
    print(" ")
    return 

sniff(iface=interface, prn=packet_callback, timeout=10)

sys.stdout = sys.__stdout__
log_file.close()
print("Sniffing done. Output saved to txop_log_output.txt")

# Saving results to a csv
with open("txop_results.csv", "w", newline="") as csvfile:
    fieldnames = ["txop_num", "duration", "termination_time", "From", "To","Ended Properly"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerows(txop_results)

print("Saved TXOP results to txop_results.csv")
