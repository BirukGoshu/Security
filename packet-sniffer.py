#!/usr/bin/env python3
import scapy.all as scapy
import optparse

def getoptions():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="this is the interface to sniff on")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] please specify an interface, use --help for more Info")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=proccess_sniffed_packet)
    
def proccess_sniffed_packet(packet):
    print(packet)
    
options = getoptions()
sniff(options.interface)