import sys
from scapy import *

if __name__ == "__main__":
    arguments = sys.argv
    ips = []

    for ip in arguments[1:]:
        ips.append(ip)

    print(ips)

    arpSpoofing = ArpSpoofing()
    arpSpoof = arpSpoofing.doSpoof()

    dnsPoisoning = DnsPoisoning()
    dnsPoison = dnsPoisoning.doPoison()
