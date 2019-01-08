import time
import sys

from scapy.all import *

def main(argc, argv):
    
    if argc != 3:
        print("Usage: %s <TargetIP> <Packet Count>" % argv[0])
        sys.exit(1)

    target, packet_count = argv[1:]
    bpf = "ip host %s" % target
    iface = "enp5s0"
    file_name = "%s_%d.pcap"  % (target, round(time.time()))

    print("[*] Sniffing traffic from %s" % target)
    packets = sniff(filter=bpf, iface=iface, count=int(packet_count))
    wrpcap(file_name, packets)
    
    sys.exit(0)


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)