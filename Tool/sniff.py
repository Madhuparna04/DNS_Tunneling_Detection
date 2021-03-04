from scapy.all import *
import sys
from io import StringIO

cache = []
common = dict()

def fil(x):
    global cache
    txt = x.summary()
    txt = txt.split(' ')[8]
    qr = txt[3:-4]
    print(qr)
    parts = []
    if qr not in common.keys():
        count=0
        l1=0
        l2=0
        for p in qr.split("."):
            if p not in parts:
                count+=1
                l1=l1+len(p)
            l2=l2+len(p)
        sim = count/len(qr.split("."))
        if l2 == 0:
            attack_data.append(0)
            return False
        sim2=l1/l2
        if sim <= 0.75 and sim2 >= 0.8:
            print("Attack" + qr)
        else:
            print("OK" + qr)
        for p in qr.split("."):
            parts.append(p)
        common[qr] = 1
    else:
        common[qr] += 1

a=sniff(lfilter=lambda x: x.haslayer(DNS) and x.getlayer(DNS).qr == 0 and fil(x), count=10)
