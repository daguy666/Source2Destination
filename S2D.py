#!/usr/bin/env python
# -----------------------------------------------------------
# Filename      : S2D.py
# Created By    : Joe Pistone
# Date Created  : 16-Mar-2016 18:16
# Date Modified :
#------------------------------------------------------------
# License       : Development
#
# Description   : Network Discovery and fingerprinting tool
#
# (c) Copyright 2015, TheKillingTime all rights reserved.
#-----------------------------------------------------------

__author__  = "Joe Pistone"
__version__ = "1.5" 

import sys
import time
import logging
# Cleans up a little of scapy's run time mess.
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
import pygeoip
import proto_to_numbers
from netaddr import *
from scapy.all import *

# Moar scapy clean up
conf.verb=0


class Inspect_Traffic(object):

    def __init__(self, p2c, interface):
        # MaxMind GeoIP database
        self.geodb = '/usr/local/geo/GeoLiteCity.dat'
        self.count = int(p2c)
        self.interface = interface
        print "\033[32;3m[*]\033[0m Capturing %d packets to analyze on interface %s ..." % (self.count, self.interface)
        self.time = time.strftime("%H:%M:%S")
        self.date = (time.strftime("%m/%d/%Y "))
        self.time_stamp = self.date + self.time
        
        # To log or to print, or both 
        self.log             = False
        self.print_to_screen = True
        #print "--DEBUG-- packet count - > %d  | interface - > %s --DEBUG--" % (self.count, self.interface)

    def log_file(self, log_to_write):
        # This is temporary <= I bet it's not. 
        # Re factor with the logging library later on.
        a = open('/var/log/packet_direction/network.log', 'a')
        a.write(log_to_write)
        a.close()

    def sniff_packets(self):
        """Let's Sniff some packets!!
        """
        try:
            self.packets = sniff(iface=self.interface, count=self.count)
        except OSError, err:
            print "\n\033[31;3m[!!]\033[0m Error: Interface %s is invalid. " % self.interface
            


    def geo_lookup(self, ip_address):
        """This method will do a geo lookup
           against an ip address.
        """
        try:
            gic = pygeoip.GeoIP(self.geodb)
        except IOError:
            print "Cannot open %s." % self.geodb
            sys.exit(1)

        try:
            geo_json = gic.record_by_addr(ip_address)
            output = ", ".join([geo_json['country_name'], geo_json['region_code']])
        except:
            output = "Unregistered"

        return output

    def hardware_vendor(self, mac):
        """This method will take a mac address
           The pull out the oui and analyze it.
        """
        try:
            hw_id = EUI(mac)
            oui = hw_id.oui
            return oui.registration().org 
        except NotRegisteredError, err:
            return 'Error="%s"' % err


    def setup_output(self):
        """This method should parse the output
           from the packet capture.
        """
        for packet in self.packets[IP]:
            pkt = packet[0][IP]
            hw_id = packet[0]['Ethernet']
    
            # Geo look-ups on source and dest.
            src_geo = self.geo_lookup(str(pkt.src))
            dst_geo = self.geo_lookup(str(pkt.dst))
            
            # Source and destination Mac addresses
            self.src_mac = 'Source Mac="%s"' % hw_id.src
            self.dst_mac   = 'Destination Mac="%s"'  % hw_id['Ethernet'].dst
            
            # Source and destination IP Address
            src = 'Source="%s"' % packet[0][IP].src
            dst   = 'Destination="%s"' % packet[0][IP].dst
           
            # Source and destination Geolookups  
            src_location = 'Location="%s"' % src_geo
            dst_location = 'Location="%s"' % dst_geo
            
            # Protocol to number lookup.
            proto_2_num = str(packet[0][IP].proto)
            time  = 'Timestamp="%s"' % self.time_stamp
            proto = 'Protocol="%s"' % proto_to_numbers.protocols[proto_2_num]
            
            # Hardware ID lookups
            src_vendor = 'HW_Vendor="%s"' % self.hardware_vendor(hw_id.src)
            dst_vendor = 'HW_Vendor="%s"' % self.hardware_vendor(hw_id.dst)
            
            # Join it all together for a log line
            self.value = " ".join([time, proto, src, src_location, self.src_mac, src_vendor, dst, dst_location, self.dst_mac, dst_vendor])
            
            # Built in logic for printing or logging to a file (or both)
            self.print_and_or_log()
            

    def print_and_or_log(self):
        """Will check to either print, log, 
           or both.
        """
        if self.log:
            self.log_file(self.value+"\n")
        
        if self.print_to_screen:
            print self.value

    def main(self):
        """Main method.
        """
        self.sniff_packets()
        self.setup_output()


if __name__ == '__main__':
    if os.getuid() == 0:
        if len(sys.argv) != 3:
            print "Usage: %s <interface> <number of packets to capture>" % sys.argv[0]
            sys.exit(1)
        # Get command line args for interface and packets to capture.
        interface = sys.argv[1]
        p2c       = sys.argv[2]

        # DEBUG
        '''
        print type(sys.argv[0])
        print type(sys.argv[1])
        print type(sys.argv[2])
        '''
        if p2c.isdigit():
            inspect = Inspect_Traffic(p2c, interface)
            inspect.main()
        else:
            print "\033[31;3m[!!]\033[0m Packet count must be a digit."
    else:
        print "\033[31;3m[!!]\033[0m Please run as root."
