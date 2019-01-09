import time
import sys

from scapy.all import *

packets_received = 0

def verbose(packet):
    global packets_received
    
    packets_received += 1
    print(packets_received)
    if packets_received % 1000 == 0:
        print(packets_received)

def main(argc, argv):
    
    if argc != 3:
        print("Usage: %s <TargetIP> <Packet Count>" % argv[0])
        sys.exit(1)

    target, packet_count = argv[1:]
    #bpf = "dst host %s and tcp port 80" % target
    bpf = "ip host %s" % target
    iface = "enp5s0"
    file_name = "%s_%d.pcap"  % (target, round(time.time()))

    print("[*] Sniffing traffic on %s" % target)
    packets = sniff(filter=bpf, iface=iface, count=int(packet_count), prn=verbose)
    wrpcap(file_name, packets)
    
    sys.exit(0)


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)