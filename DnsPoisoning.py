import sys
from scapy.all import *

class DnsPoisoning:

    def __init__(self):
        pass

    def doPoison(self, hostToAttack, url):
        print("You are poisoned")