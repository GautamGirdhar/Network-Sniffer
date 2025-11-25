import argparse
import scapy.all as scapy
from scapy.layers import http
import logging
from typing import Optional
import signal
import sys
from datetime import datetime
from collections import defaultdict
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

class NetworkSniffer:
    def __init__(self, interface: Optional[str] = None, filter_protocol: Optional[str] = None, 
                 bpf_filter: Optional[str] = None, output_file: Optional[str] = None):
        self.interface = interface
        self.filter_protocol = filter_protocol
        self.bpf_filter = bpf_filter
        self.output_file = output_file
        self.packets_captured = []
        
        # Statistics tracking
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'https_packets': 0,
            'other_packets': 0,
            'protocol_count': defaultdict(int),
            'start_time': None,
            'end_time': None
        }
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.YELLOW}🛑 Stopping packet capture...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*70}\n")
        self.display_statistics()
        
        if self.output_file and self.packets_captured:
            self.save_packets()
        
        sys.exit(0)

    def get_protocol_name(self, packet) -> str:
        """Get human-readable protocol name"""
        if scapy.TCP in packet:
            port = packet[scapy.TCP].dport
            if port == 80 or port == 8080:
                return "HTTP"
            elif port == 443:
                return "HTTPS"
            elif port == 22:
                return "SSH"
            elif port == 21:
                return "FTP"
            elif port == 23:
                return "TELNET"
            elif port == 25:
                return "SMTP"
            elif port == 53:
                return "DNS"
            else:
                return "TCP"
        elif scapy.UDP in packet:
            port = packet[scapy.UDP].dport
            if port == 53:
                return "DNS"
            elif port == 67 or port == 68:
                return "DHCP"
            else:
                return "UDP"
        elif scapy.ICMP in packet:
            return "ICMP (Ping)"
        elif scapy.ARP in packet:
            return "ARP"
        else:
            return "OTHER"

    def get_protocol_emoji(self, protocol: str) -> str:
        """Get emoji for protocol"""
        emoji_map = {
            'HTTP': '🌐',
            'HTTPS': '🔒',
            'TCP': '📡',
            'UDP': '📤',
            'ICMP (Ping)': '🏓',
            'DNS': '🔍',
            'SSH': '🔐',
            'FTP': '📁',
            'ARP': '🔗',
            'DHCP': '⚙️',
            'SMTP': '📧',
            'TELNET': '💻',
            'OTHER': '❓'
        }
        return emoji_map.get(protocol, '📦')

    def format_packet_summary(self, packet) -> str:
        """Create a beautiful, human-readable packet summary"""
        if not scapy.IP in packet:
            return None
        
        protocol = self.get_protocol_name(packet)
        emoji = self.get_protocol_emoji(protocol)
        
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Get port information
        src_port = dst_port = "N/A"
        if scapy.TCP in packet:
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif scapy.UDP in packet:
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
        
        # Get packet size
        packet_size = len(packet)
        
        # Color coding based on protocol
        if protocol in ['HTTP', 'HTTPS']:
            color = Fore.GREEN
        elif protocol in ['SSH', 'TELNET']:
            color = Fore.CYAN
        elif protocol == 'ICMP (Ping)':
            color = Fore.YELLOW
        elif protocol in ['TCP', 'UDP']:
            color = Fore.BLUE
        else:
            color = Fore.WHITE
        
        summary = f"{color}{emoji} {protocol:<12} {Style.RESET_ALL}"
        summary += f"{Fore.MAGENTA}{src_ip}:{src_port}{Style.RESET_ALL} "
        summary += f"{Fore.WHITE}→{Style.RESET_ALL} "
        summary += f"{Fore.CYAN}{dst_ip}:{dst_port}{Style.RESET_ALL} "
        summary += f"{Fore.YELLOW}[{packet_size} bytes]{Style.RESET_ALL}"
        
        # Add HTTP details if available
        if http.HTTPRequest in packet:
            if packet[http.HTTPRequest].Host and packet[http.HTTPRequest].Path:
                host = packet[http.HTTPRequest].Host.decode()
                path = packet[http.HTTPRequest].Path.decode()
                summary += f"\n   {Fore.GREEN}   ↳ {host}{path}{Style.RESET_ALL}"
        
        return summary

    def update_statistics(self, packet):
        """Update packet statistics"""
        self.stats['total_packets'] += 1
        
        protocol = self.get_protocol_name(packet)
        self.stats['protocol_count'][protocol] += 1
        
        if scapy.TCP in packet:
            self.stats['tcp_packets'] += 1
        if scapy.UDP in packet:
            self.stats['udp_packets'] += 1
        if scapy.ICMP in packet:
            self.stats['icmp_packets'] += 1
        if protocol == 'HTTP':
            self.stats['http_packets'] += 1
        if protocol == 'HTTPS':
            self.stats['https_packets'] += 1

    def packet_callback(self, packet):
        """Callback function for packet processing"""
        try:
            if not scapy.IP in packet:
                return
            
            # Apply protocol filter if specified
            if self.filter_protocol:
                if self.filter_protocol.lower() == 'tcp' and not scapy.TCP in packet:
                    return
                if self.filter_protocol.lower() == 'udp' and not scapy.UDP in packet:
                    return
                if self.filter_protocol.lower() == 'http' and not http.HTTP in packet:
                    return
            
            # Store packet for saving
            self.packets_captured.append(packet)
            
            # Update statistics
            self.update_statistics(packet)
            
            # Display packet summary
            summary = self.format_packet_summary(packet)
            if summary:
                print(f"\n{summary}")
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def display_statistics(self):
        """Display beautiful capture statistics"""
        if self.stats['start_time']:
            self.stats['end_time'] = datetime.now()
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        else:
            duration = 0
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}📊 CAPTURE STATISTICS")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}⏱️  Duration:{Style.RESET_ALL} {duration:.2f} seconds")
        print(f"{Fore.GREEN}📦 Total Packets:{Style.RESET_ALL} {self.stats['total_packets']}")
        print(f"{Fore.GREEN}💾 Packets Per Second:{Style.RESET_ALL} {self.stats['total_packets']/duration if duration > 0 else 0:.2f}")
        
        print(f"\n{Fore.YELLOW}Protocol Breakdown:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'─'*70}{Style.RESET_ALL}")
        
        # Sort protocols by count
        sorted_protocols = sorted(self.stats['protocol_count'].items(), 
                                 key=lambda x: x[1], reverse=True)
        
        for protocol, count in sorted_protocols:
            percentage = (count / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
            emoji = self.get_protocol_emoji(protocol)
            bar_length = int(percentage / 2)
            bar = '█' * bar_length
            print(f"{emoji} {protocol:<12} {Fore.CYAN}{bar}{Style.RESET_ALL} {count:>5} ({percentage:>5.1f}%)")
        
        if self.output_file:
            print(f"\n{Fore.GREEN}💾 Packets saved to:{Style.RESET_ALL} {self.output_file}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    def save_packets(self):
        """Save captured packets to PCAP file"""
        try:
            scapy.wrpcap(self.output_file, self.packets_captured)
            self.logger.info(f"Saved {len(self.packets_captured)} packets to {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error saving packets: {e}")

    def start_sniffing(self, packet_count: int = 0):
        """Start packet sniffing"""
        try:
            # Display startup banner
            print(f"\n{Fore.MAGENTA}{'='*70}")
            print(f"{Fore.MAGENTA}🔍 NETWORK PACKET SNIFFER")
            print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}\n")
            
            print(f"{Fore.GREEN}📡 Interface:{Style.RESET_ALL} {self.interface or 'Default'}")
            print(f"{Fore.GREEN}🎯 Protocol Filter:{Style.RESET_ALL} {self.filter_protocol or 'All Protocols'}")
            print(f"{Fore.GREEN}🔧 BPF Filter:{Style.RESET_ALL} {self.bpf_filter or 'None'}")
            print(f"{Fore.GREEN}📊 Packet Limit:{Style.RESET_ALL} {packet_count if packet_count > 0 else 'Unlimited'}")
            print(f"{Fore.GREEN}💾 Output File:{Style.RESET_ALL} {self.output_file or 'Not saving'}")
            
            print(f"\n{Fore.YELLOW}Press Ctrl+C to stop capture and view statistics...{Style.RESET_ALL}\n")
            print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")
            
            self.stats['start_time'] = datetime.now()
            
            # Start sniffing with BPF filter support
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.packet_callback,
                count=packet_count if packet_count > 0 else 0,
                store=False  # Don't store in memory (we handle it manually)
            )
            
            # If we reach here (no Ctrl+C), display stats
            self.display_statistics()
            
            if self.output_file and self.packets_captured:
                self.save_packets()
                
        except PermissionError:
            self.logger.error("Permission denied. Try running with sudo/administrator privileges.")
        except Exception as e:
            self.logger.error(f"Sniffing error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='🔍 Professional Network Packet Sniffer with BPF Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture all traffic
  sudo python sniffer.py
  
  # Capture only TCP traffic on eth0
  sudo python sniffer.py -i eth0 -p tcp
  
  # Use BPF filter to capture HTTP traffic to port 80
  sudo python sniffer.py -b "tcp port 80"
  
  # Capture 100 packets and save to file
  sudo python sniffer.py -c 100 -o capture.pcap
  
  # Capture HTTPS traffic with BPF filter
  sudo python sniffer.py -b "tcp port 443" -o https_traffic.pcap
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       help='Network interface to sniff on (e.g., eth0, wlan0)', 
                       default=None)
    
    parser.add_argument('-p', '--protocol', 
                       help='Filter specific protocol', 
                       choices=['tcp', 'udp', 'http'], 
                       default=None)
    
    parser.add_argument('-b', '--bpf', 
                       help='BPF (Berkeley Packet Filter) expression (e.g., "tcp port 80")', 
                       default=None,
                       metavar='FILTER')
    
    parser.add_argument('-c', '--count', 
                       help='Number of packets to capture (0 = unlimited)', 
                       type=int, 
                       default=0)
    
    parser.add_argument('-o', '--output', 
                       help='Output PCAP file to save captured packets', 
                       default=None,
                       metavar='FILE')
    
    args = parser.parse_args()
    
    # Create sniffer instance
    sniffer = NetworkSniffer(
        interface=args.interface,
        filter_protocol=args.protocol,
        bpf_filter=args.bpf,
        output_file=args.output
    )
    
    # Start sniffing
    sniffer.start_sniffing(packet_count=args.count)

if __name__ == '__main__':
    main()