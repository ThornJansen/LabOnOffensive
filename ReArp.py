import sys
from scapy.all import *

if __name__ == "__main__":
    # global variables
    arguments = sys.argv
    interface = "enp0s3"
    target1 = []
    target1MAC = []
    target2 = []
    target2MAC = []
    arpPartList = []

    '''
    ips = raw_input("Enter range of IPs you scanned for before: (e.g 192.168.56.0/24): ")
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips), timeout=2, iface=interface, inter=0.1)
    counter = 0
    ipList = []
    macList = []
    for snt, recv in ans:
        print("index: {} IP: {} MAC: {}".format(counter, recv[ARP].psrc, recv[ARP].hwsrc))
        ipList.append(recv[ARP].psrc)
        macList.append(recv[ARP].hwsrc)
        counter += 1
    index = ""
    while index != "no":
        index = raw_input("Enter the index of one of the IPs you added to Target 1 before, or no if you are done adding IPs: ")
        if index != "no":
            intIndex = int(index)
            target1.append(ipList[intIndex])
            target1MAC.append(macList[intIndex])
            index = raw_input("IP added, do you want to select more IP addresses? Write yes or no: ")
    index2 = ""
    while index2 != "no":
        index2 = raw_input("Enter the index of one of the IPs you added to Target 2 before, or no if you are done adding IPs: ")
        if index2 != "no":
            intIndex2 = int(index2)
            target2.append(ipList[intIndex2])
            target2MAC.append(macList[intIndex2])
            index2 = raw_input("IP added, do you want to select more IP addresses? Write yes or no: ")
    '''

    # open file and read the content in a list
    with open('target1ListIP.txt', 'r') as file1:
        for line in file1:
            # remove linebreak which is the last character of the string
            currentPlace = line[:-1]

            # add item to the list
            target1.append(currentPlace)

    with open('target2ListIP.txt', 'r') as file2:
        for line in file2:
            # remove linebreak which is the last character of the string
            currentPlace = line[:-1]

            # add item to the list
            target2.append(currentPlace)

    with open('target1ListMAC.txt', 'r') as file3:
        for line in file3:
            # remove linebreak which is the last character of the string
            currentPlace = line[:-1]

            # add item to the list
            target1MAC.append(currentPlace)

    with open('target1ListIP.txt', 'r') as file4:
        for line in file4:
            # remove linebreak which is the last character of the string
            currentPlace = line[:-1]

            # add item to the list
            target2MAC.append(currentPlace)

    for i in range(len(target1)):
        for j in range(len(target2)):
            arpPart = ARP(op="who-has", hwsrc=target2MAC[j], psrc=target2[j], hwdst=target1MAC[i], pdst=target1[i])
            arpPartList.append(arpPart)
            arpPart = ARP(op="who-has", hwsrc=target1MAC[i], psrc=target1[i], hwdst=target2MAC[j], pdst=target2[j])
            arpPartList.append(arpPart)

    for item in arpPartList:
        send(item, iface=interface, verbose=False)

