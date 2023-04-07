#!/usr/bin/env python3

from scapy.all import *


def handler(packet):
    print(packet.summary())


if __name__ == "__main__":
    sniff(iface="ogstun", prn=handler, filter="tcp" ,store=0)