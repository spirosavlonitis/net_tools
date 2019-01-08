import sys

from scapy.all import *
from socket import socket, AF_INET, SOCK_DGRAM
from netaddr import IPNetwork
from time import sleep
from threading import Thread

def udp_sender(subnet):
    """Send a udp message to the entire subnet"""

    sleep(5)
    sender = socket(AF_INET, SOCK_DGRAM, 0)

    print("[*] Sending UDP message to subnet %s" % subnet)
    for ip in IPNetwork(subnet):
        try:
            sender.sendto("PYTHONRULES!".encode(), (str(ip), 65212))
        except:
            pass

def packet_scanner(packet):
    """Check ICMP message for Port Unreachable response"""

    if packet[ICMP].type == 3 and packet[ICMP].code == 3:
        print("[*] Host %s Up" % packet[IP].src)

def main(argc, argv):
    
    if argc != 2:
        print("Usage: %s <Subnet>" % argv[0])
        sys.exit(1)

    Thread(target=udp_sender, args=(argv[1],)).start()

    print("[*] Scanning for hosts")
    sniff(filter="icmp", prn=packet_scanner, store=0)


if __name__ == '__main__':
    main(len(sys.argv), sys.argv)