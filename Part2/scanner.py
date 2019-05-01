import dpkt
import sys
import binascii
import socket
import pprint

# ARP Spoofing functions and variables

# Reference: https://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
def add_colons_to_mac(mac_addr):
    """This function accepts a 12 hex digit string and converts it to a colon
    separated string"""
    s = list()
    for i in range(12 / 2):  # mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append(mac_addr[i * 2:i * 2 + 2])
    r = ":".join(s)
    return r


def detectArpSpoofing(filename, arp_spoofing_devices):
    f = open(filename, "rb")
    pcap = dpkt.pcap.Reader(f)
    frame_counter = 0
    for ts, buf in pcap:
        ether = dpkt.ethernet.Ethernet(buf)
        frame_counter += 1
        if ether.type == dpkt.ethernet.ETH_TYPE_ARP:
            arp = ether.arp
            if arp.op == dpkt.arp.ARP_OP_REPLY:
                src_ip = socket.inet_ntoa(arp.spa)
                src_mac = add_colons_to_mac(binascii.hexlify(arp.sha))

                # getting the MAC for the src IP in ARP reply
                mac_for_src_ip = None
                if arp_spoofing_devices.has_key(src_ip):
                    mac_for_src_ip = arp_spoofing_devices[src_ip]

                # getting the IP for the src MAC in ARP reply
                ip_for_src_mac = None
                if arp_spoofing_devices.has_key(src_mac):
                    ip_for_src_mac = arp_spoofing_devices[src_mac]

                # If mac is in the devices list but ip is not matching
                if ip_for_src_mac is not None and ip_for_src_mac != src_ip:
                    print "ARP spoofing!"
                    print "MAC:", src_mac
                    print "Packet number:", frame_counter, "\n"
                # If mac is in the devices list but ip is not matching
                elif mac_for_src_ip is not None and mac_for_src_ip != src_mac:
                    print "ARP spoofing!"
                    print "MAC:", src_mac
                    print "Packet number:", frame_counter, "\n"

# Port scanning functions and variables


def detectPortScan(filename, port_scans, port_scans_packets):
    f = open(filename, "rb")
    pcap = dpkt.pcap.Reader(f)
    frame_counter = 0
    TCP_PROTOCOL = 6
    UDP_PROTOCOL = 17
    for ts, buf in pcap:
        ether = dpkt.ethernet.Ethernet(buf)
        frame_counter += 1
        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = ether.data
            transport_layer = ip.data
            dst_ip = socket.inet_ntoa(ip.dst)

            # Initializing the dictionary for packet number and ports
            if not port_scans.has_key(dst_ip):
                port_scans[dst_ip] = set()
                port_scans_packets[dst_ip] = list()

            # Checking if a TCP SYN packet
            if ip.p == TCP_PROTOCOL and (transport_layer.flags & dpkt.tcp.TH_SYN) != 0:
                port = transport_layer.dport
                port_scans.get(dst_ip).add(port)
                port_scans_packets.get(dst_ip).append(frame_counter)
            elif ip.p == UDP_PROTOCOL:  # Checking if UDP packet
                port = transport_layer.dport
                port_scans.get(dst_ip).add(port)
                port_scans_packets.get(dst_ip).append(frame_counter)

    for ip, ports in port_scans_packets.iteritems():
        if len(ports) >= 100:
            print "Port scan!"
            print "IP:", ip
            print "Packet number:", str(port_scans_packets.get(ip))


if __name__ == '__main__':
    """
    arp_spoofing_devices = dict()
    arp_spoofing_devices["192.168.0.100"] = "7c:d1:c3:94:9e:b8"
    arp_spoofing_devices["192.168.0.103"] = "d8:96:95:01:a5:c9"
    arp_spoofing_devices["192.168.0.1"] = "f8:1a:67:cd:57:6e"

    arp_spoofing_devices["7c:d1:c3:94:9e:b8"] = "192.168.0.100"
    arp_spoofing_devices["d8:96:95:01:a5:c9"] = "192.168.0.103"
    arp_spoofing_devices["f8:1a:67:cd:57:6e"] = "192.168.0.1"

    detectArpSpoofing(sys.argv[1], arp_spoofing_devices)

    port_scans = dict()
    port_scans_packets = dict()

    detectPortScan(sys.argv[1], port_scans, port_scans_packets)
    """

