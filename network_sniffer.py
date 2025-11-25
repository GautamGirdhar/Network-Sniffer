import argparse
import scapy.all as scapy
from scapy.layers import http
import logging
from typing import Optional

class NetworkSniffer:
    def __init__(self, interface: Optional[str] = None, filter_protocol: Optional[str] = None):
        self.interface = interface
        self.filter_protocol = filter_protocol
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)

    def get_protocol_details(self, packet):
        """
        Extract and return detailed protocol information
        """
        details = {}
        if scapy.IP in packet:
            details['Source IP'] = packet[scapy.IP].src
            details['Destination IP'] = packet[scapy.IP].dst
        if scapy.TCP in packet:
            details['Source Port'] = packet[scapy.TCP].sport
            details['Destination Port'] = packet[scapy.TCP].dport
        if scapy.UDP in packet:
            details['Source Port'] = packet[scapy.UDP].sport
            details['Destination Port'] = packet[scapy.UDP].dport
        if http.HTTP in packet:
            details['Protocol'] = 'HTTP'
        return details

    def packet_callback(self, packet):
        """
        Callback function for packet processing
        """
        try:
            if not scapy.IP in packet:
                return
            if self.filter_protocol:
                if self.filter_protocol.lower() == 'tcp' and not scapy.TCP in packet:
                    return
                if self.filter_protocol.lower() == 'udp' and not scapy.UDP in packet:
                    return
                if self.filter_protocol.lower() == 'http' and not http.HTTP in packet:
                    return
            details = self.get_protocol_details(packet)
            print(f"Captured Packet: {details}")
        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_sniffing(self, packet_count: int = 100):
        """
        Start packet sniffing
        """
        try:
            print(f"Starting network sniffer on interface {self.interface}")
            print(f"Capture filter: {self.filter_protocol or 'All Protocols'}")
            scapy.sniff(iface=self.interface, prn=self.packet_callback, count=packet_count)
        except Exception as e:
            print(f"Sniffing error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Basic Network Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on', default=None)
    parser.add_argument('-p', '--protocol', help='Filter specific protocol (tcp/udp/http)', choices=['tcp', 'udp', 'http'], default=None)
    parser.add_argument('-c', '--count', help='Number of packets to capture', type=int, default=100)
    args = parser.parse_args()
    
    sniffer = NetworkSniffer(interface=args.interface, filter_protocol=args.protocol)
    sniffer.start_sniffing(packet_count=args.count)

if __name__ == '__main__':
    main()
