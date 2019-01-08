import time

from scapy.all import *
from sys import exit


def main(argc, argv):
    
    if argc != 3:
        print("Usage: %s <TargetIP> <Packet Count>", % argv[0])
        exit(1)

    target, packet_count = argv[1:]
    bpf = "ip host %s" % target
    iface = "enp5s0"
    file_name = "%s_%d.pcap"  % (target, round(time.time()))

    packets = sniff(filter=bpf, iface=iface, count=int(packet_count))
    wrpcap(file_name, packets)
    
    exit(0)
