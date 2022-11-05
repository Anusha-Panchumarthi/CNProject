import pyshark
import matplotlib.pyplot as plt
import sys
import nest_asyncio

def tcp_header_flags():
    
    dict = {}
    colors = ['#320e3b', '#e56399', '#7f96ff', '#a6cfd5', '#49a078', '#7D80DA', '#993955', '#db4c40', '#783F8E', '#343F3E']
    cap = pyshark.FileCapture(r'C:/Users/anush/CNProject/ult.pcapng')
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
    plot2 = plt.figure(0)
    plt.title("TCP HEADER FLAGS") 
    plt.ylabel('No. of packets')
    plt.xlabel('Header flags')
    plt.bar(keys, values, color=colors)
    
    plt.savefig('header_flags.jpg')
    print("Saved as header_flags.jpg")

def transport_protocols():
    dict = {}
    colors = ['#db4c40', '#783F8E', '#343F3E']
    cap = pyshark.FileCapture(r'C:/Users/anush/CNProject/ult.pcapng')
    for pkt in cap:
        protocol = pkt.transport_layer
        if protocol == 'TCP':
            dict['TCP'] = dict.get('TCP', 0) + 1
        elif protocol == 'UDP':
            dict['UDP'] = dict.get('UDP', 0) + 1
    
    keys = dict.keys()
    values = dict.values()
    print("Loading.....")
    plot1 = plt.figure(1)
    plt.title("TRANSPORT PROTOCOLS") 
    plt.ylabel('No. of packets')
    plt.xlabel('Transport Protocols')
    plt.bar(keys, values, color=colors, width=0.2, align='center')
    plt.savefig('protocols.jpg')
    print("Saved as protocols.jpg")

if __name__ == "__main__":
    sys.tracebacklimit = 0
    nest_asyncio.apply()
    tcp_header_flags()
    transport_protocols()