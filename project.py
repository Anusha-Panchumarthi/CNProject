import pyshark
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.colors as mcolors

def tcp_header_flags():
    
    dict = {}
    colors = ['#320e3b', '#e56399', '#7f96ff', '#a6cfd5', '#49a078', '#7D80DA', '#993955', '#db4c40', '#783F8E', '#343F3E']
    cap = pyshark.FileCapture(r'C:/Users/anush/temp/ult.pcapng')
    for pkt in cap:
        #x = pkt.tcp
        if pkt.transport_layer != 'TCP':
            continue
        elif pkt.transport_layer == 'TCP': 
            x = pkt.tcp
            if x.flags_ack=="1":
                if x.flags_urg == "1":
                    dict["URG_ACK"] = dict.get("URG_ACK", 0) + 1
                elif x.flags_syn == "1":
                    dict["SYN_ACK"] = dict.get("SYN_ACK", 0) + 1
                elif x.flags_push == "1":
                    dict["PSH_ACK"] = dict.get("PSH_ACK", 0) + 1
                elif x.flags_fin == "1":
                    dict["FIN_ACK"] = dict.get("FIN_ACK", 0) + 1
                elif x.flags_reset == "1":
                    dict["RST_ACK"] = dict.get("RST_ACK", 0) + 1
            else:
                if x.flags_urg == "1":
                    dict["URG"] = dict.get("URG", 0) + 1
                elif x.flags_syn == "1":
                    dict["SYN"] = dict.get("SYN", 0) + 1
                elif x.flags_push == "1":
                    dict["PSH"] = dict.get("PSH", 0) + 1
                elif x.flags_fin == "1":
                    dict["FIN"] = dict.get("FIN", 0) + 1
                elif x.flags_reset == "1":
                    dict["RST"] = dict.get("RST", 0) + 1
    

    keys = dict.keys()
    values = dict.values()
    print("Loading.....")
    plt.title("TCP HEADER FLAGS") 
    plt.ylabel('No. of packets')
    plt.xlabel('Header flags')
    plt.bar(keys, values, color=colors)
    
    plt.savefig('header_flags.jpg')
    print("Saved as header_flags.jpg")

if __name__ == "__main__":
    tcp_header_flags()
    #transport_protocols()