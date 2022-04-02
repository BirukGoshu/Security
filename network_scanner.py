import subprocess
import optparse
import scapy.all as scapy

def getoptions():
    parser = optparse.OptionParser()
    parser.add_option("-r","--ip_range",dest="ip",help="enter the ip range to scan")
    (options,arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-]please enter an ip range to scan")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered, unanswered = scapy.srp(arp_request_broadcast,timeout=10)
    # print(answered.summary())
    print("IP \t\t\t MAC\n--------------------------------------------")
    for element in answered:
        print(element[1].psrc+ "\t\t" +element[1].hwsrc)
        print("--------------------------------------------")
    # scapy.arping(ip)


options = getoptions()
scan(options.ip)