import dpkt
import sys
import binascii
import socket


device = dict()
device["192.168.0.100"] = "7c:d1:c3:94:9e:b8"
device["192.168.0.103"] = "d8:96:95:01:a5:c9"
device["192.168.0.1"] = "f8:1a:67:cd:57:6e"

device["7c:d1:c3:94:9e:b8"] = "192.168.0.100"
device["d8:96:95:01:a5:c9"] = "192.168.0.103"
device["f8:1a:67:cd:57:6e"] = "192.168.0.1"

def add_colons_to_mac(mac_addr):
    """This function accepts a 12 hex digit string and converts it to a colon
separated string"""
    s = list()
    for i in range(12 / 2):  # mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append(mac_addr[i * 2:i * 2 + 2])
    r = ":".join(s)
    return r


def detectArpSpoofing(filename):
    f = open(filename, "rb")
    pcap = dpkt.pcap.Reader(f)
    frame_counter = 0
    count = 0
    for ts, buf in pcap:
        ether = dpkt.ethernet.Ethernet(buf)
        frame_counter += 1
        if ether.type == dpkt.ethernet.ETH_TYPE_ARP:
            arp = ether.arp
            if arp.op == dpkt.arp.ARP_OP_REPLY:
                src_ip = socket.inet_ntoa(arp.spa)
                #dst_ip = socket.inet_ntoa(arp.tpa)
                src_mac = add_colons_to_mac(binascii.hexlify(arp.sha))
                #dst_mac = add_colons_to_mac(binascii.hexlify(arp.tha))

                ip_for_src_mac = device[src_mac]
                if ip_for_src_mac != src_ip:
                    print "ARP spoofing!"
                    print "MAC:", src_mac
                    print "Packet number:", frame_counter

if __name__ == '__main__':
    detectArpSpoofing(sys.argv[1])
