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

    '''
    #checks if amount of passed arguments is correct
    if len(sys.argv) != argReq:
        print("Wrong amount of arguments provide", argReq-1, "arguments")
        sys.exit(1)
    '''

    #Takes the command like argument and stores it
    modeOfAttack = arguments[1]
    timeSleep = arguments[2]

    '''
    if modeOfAttack == "arp":
        if len(listArguments) != 3:
            print("Wrong amount of arguments provided, exiting...")
            sys.exit(0)
        else:
            hostToAttack = listArguments[1]
            hostToSpoof = listArguments[2]
    elif modeOfAttack == "dns":
        if len(listArguments) != 4:
            print("Wrong amount of arguments provided, exiting...")
            sys.exit(0)
        else:
            hostToAttack = listArguments[1]
            ipToSendTo = listArguments[2]
            url = listArguments[3]
    elif modeOfAttack == "all":
        if len(listArguments) != 5:
            print("Wrong amount of arguments provided, exiting...")
            sys.exit(0)
        else:
            hostToAttack = listArguments[1]
            hostToSpoof = listArguments[2]
            ipToSendTo = listArguments[3]
            url = listArguments[4]
    '''
    if modeOfAttack == "arp":
        nextOneAttack = "yes"
        while nextOneAttack == "yes":
            attackIp = raw_input("Please enter ip adress to attack: ")
            nextOneAttack = raw_input("If you want to enter another IP addres to attack type yes, otherwise type no. ")
            hostToAttack.append(attackIp)
        spoofIp = raw_input("Please enter ip adress to spoof: ")
        hostToSpoof = spoofIp
    elif modeOfAttack == "dns":
        nextOneAttack = "yes"
        while nextOneAttack == "yes":
            attackIp = raw_input("Please enter ip adress to attack: ")
            nextOneAttack = raw_input("If you want to enter another IP addres to attack type yes, otherwise type no. ")
            hostToAttack.append(attackIp)
        ipSendTo = raw_input("Please enter ip adress to which the URL must go to: ")
        ipToSendTo = ipSendTo
        urlNext = "yes"
        while urlNext == "yes":
            newUrl = raw_input("Please enter the URL you want to DNS spoof: ")
            urlNext = raw_input("If you want to enter another URL to DNS spoof type yes, otherwise type no. ")
            hostToAttack.append(newUrl)
    elif modeOfAttack == "all":
        nextOneAttack = "yes"
        while nextOneAttack == "yes":
            attackIp = raw_input("Please enter ip adress to attack: ")
            nextOneAttack = raw_input("If you want to enter another IP addres to attack type yes, otherwise type no. ")
            hostToAttack.append(attackIp)
        spoofIp = raw_input("Please enter ip adress to spoof: ")
        hostToSpoof = spoofIp
        ipSendTo = raw_input("Please enter ip adress to which the URL must go to: ")
        ipToSendTo = ipSendTo
        urlNext = "yes"
        while urlNext == "yes":
            newUrl = raw_input("Please enter the URL you want to DNS spoof: ")
            urlNext = raw_input("If you want to enter another URL to DNS spoof type yes, otherwise type no. ")
            hostToAttack.append(newUrl)
    else:
        print("Wrong mode of attack provided choose out of: arp, dns or all")
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
