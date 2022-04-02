import subprocess
import optparse
import re

def getoptions():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="this is the interface to change mac")
    parser.add_option("-m","--new_mac",dest="new_mac",help="The new mac to change interface to")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] please specify an interface, use --help for more Info")
    elif not options.new_mac:
        parser.error("[-] please specify a new MAC, use --help for more Info")
    return options

def changemac(interface,new_mac):
    print("[+] changing MAC address for "+interface+" to "+new_mac)
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig",interface,"up"])

def check_change(interface):
        ifconfig_result = subprocess.check_output(["ifconfig",interface])
        mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(ifconfig_result))
        
        if mac_address:
            return mac_address.group(0)
        else:
            print("[-] can not read MAC address")

options = getoptions()
current_mac = check_change(options.interface)
print("[+]current MAC is "+str(current_mac))
changemac(options.interface,options.new_mac)
current_mac = check_change(options.interface)
if current_mac == options.new_mac:
    print("[+]MAC address of "+options.interface+" has been changed")
else:
    print("[-]MAC address of "+options.interface+" wasn't changed")