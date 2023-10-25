from scapy.all import *
import random
import time
import re

class PortScanner:
    def __init__(self):
        self.PACKETS = []

    def sniff_packets(self):
        print("Enter the number of packets to be sniffed")
        count = input()
        self.PACKETS = sniff(count=int(count))
        print("-----------------------------------------------------------------")
        print("SNIFFING COMPLETED!")
        print("-----------------------------------------------------------------")
        self.load_sniffed_packets()

    def load_sniffed_packets(self):
        try:
            print("-----------------------------------------------------------------")
            print("1) Print all Packets\n2) Apply Filters\n3) View Packet Data ")
            option = int(input())
            if option == 1:
                loop = 1
                for k in self.PACKETS:
                    print("-----------------------------------------------------------------")
                    print(f"{loop} PACKET:")
                    print("-----------------------------------------------------------------")
                    print(k.show())
                    print("Payload:")
                    print(k.payload)
                    print("-----------------------------------------------------------------")
                    loop += 1
                time.sleep(1.5)
            elif option == 2:
                self.apply_filters()
            elif option == 3:
                self.view_packet_data()
            else:
                print("Invalid INPUT")

        except Exception as e:
            print(f"Error: {str(e)}")
            print("NO PACKETS HAVE BEEN CAPTURED YET")
        time.sleep(1.5)
        self.menu()

    def view_packet_data(self):
        try:
            print("Enter the packet number to view its data:")
            packet_number = int(input())
            if 1 <= packet_number <= len(self.PACKETS):
                selected_packet = self.PACKETS[packet_number - 1]
                print("-----------------------------------------------------------------")
                print(f"Packet {packet_number} Data:")
                print("-----------------------------------------------------------------")
                print(selected_packet.payload)
                print("-----------------------------------------------------------------")
                time.sleep(1.5)
            else:
                print("Invalid packet number. Please enter a number within the range.")
                time.sleep(1.5)
        except ValueError as e:
            print(f"Error: {str(e)}")
            print("Invalid input. Please enter a valid number.")
            time.sleep(1.5)

    def apply_filters(self):
        print("-----------------------------------------------------------------")
        print("Select Filter:")
        print("1) HTTP Filter")
        print("2) ARP Filter")
        print("3) TCP Filter")
        print("4) UDP Filter")
        print("5) Back to Menu")
        filter_option = int(input())

        if filter_option == 1:
            http_packets = [packet for packet in self.PACKETS if packet.haslayer(TCP) and packet.dport == 80]
            if http_packets:
                for i, http_packet in enumerate(http_packets, 1):
                    print(f"------------------- HTTP Packet {i} -------------------")
                    print(http_packet.show())
                    
                    # Extracting user credentials from HTTP POST requests (example)
                    if http_packet.haslayer(Raw) and b'POST' in http_packet[Raw].load:
                        data = http_packet[Raw].load.decode('utf-8')
                        # Extracting username (you may need to adapt this based on the actual login form structure)
                        username = re.search(r'username=(.*?)&', data)
                        if username:
                            print(f"Username: {username.group(1)}")
                        # Extracting password (similarly, adapt based on the form structure)
                        password = re.search(r'password=(.*?)&', data)
                        if password:
                            print(f"Password: {password.group(1)}")
                        
                    print("--------------------------------------------------------")
            else:
                print("No HTTP packets found.")
        elif filter_option == 2:
            arp_packets = [packet for packet in self.PACKETS if packet.haslayer(ARP)]
            if arp_packets:
                for i, arp_packet in enumerate(arp_packets, 1):
                    print(f"------------------- ARP Packet {i} -------------------")
                    print(arp_packet.show())
                    print("Payload:")
                    print(arp_packet.payload)
                    print("--------------------------------------------------------")
            else:
                print("No ARP packets found.")
        elif filter_option == 3:
            tcp_packets = [packet for packet in self.PACKETS if packet.haslayer(TCP)]
            if tcp_packets:
                for i, tcp_packet in enumerate(tcp_packets, 1):
                    print(f"------------------- TCP Packet {i} -------------------")
                    print(tcp_packet.show())
                    print("Payload:")
                    print(tcp_packet.payload)
                    print("--------------------------------------------------------")
            else:
                print("No TCP packets found.")
        elif filter_option == 4:
            udp_packets = [packet for packet in self.PACKETS if packet.haslayer(UDP)]
            if udp_packets:
                for i, udp_packet in enumerate(udp_packets, 1):
                    print(f"------------------- UDP Packet {i} -------------------")
                    print(udp_packet.show())
                    print("Payload:")
                    print(udp_packet.payload)
                    print("--------------------------------------------------------")
            else:
                print("No UDP packets found.")
        elif filter_option == 5:
            self.menu()
        else:
            print("Invalid option. Please try again.")
            self.apply_filters()

    def port_scan(self, host, start_port, end_port, protocol):
        ip = IP(dst=host)

        for dst_port in range(start_port, end_port + 1):
            response = None

            if protocol.lower() == 'tcp':
                response = sr1(ip/TCP(dport=dst_port), timeout=1, verbose=0)
            elif protocol.lower() == 'udp':
                response = sr1(ip/UDP(dport=dst_port), timeout=1, verbose=0)
            elif protocol.lower() == 'ftp' and (20 <= dst_port <= 21):
                pass
            elif protocol.lower() == 'imap' and dst_port == 143:
                pass
            elif protocol.lower() == 'ssh' and dst_port == 22:
                pass
            elif protocol.lower() == 'sip' and dst_port == 5060:
                pass
            else:
                print(f"Unsupported protocol: {protocol}")
                return

            if response is not None:
                if response.haslayer(ICMP):
                    print(f"{host}:{dst_port} is filtered (silently dropped) for {protocol.upper()}.")
                elif response.haslayer(TCP) and response[TCP].flags == 0x12:
                    print(f"{host}:{dst_port} is open for {protocol.upper()}.")
                else:
                    print(f"{host}:{dst_port} is closed for {protocol.upper()}.")
            else:
                print(f"No response received for {protocol.upper()} port {dst_port} on {host}.")

    def menu(self):
        menu_loop = 0
        while menu_loop == 0:
            print("-----------------------------------------------------------------")
            print("       _____ _   __ ____ _____ _____ _____ _______         ")
            print("      / ___// | / /_  _// ___// ___//  __//  __  /        ")
            print("      \__ \/  |/ / / / / /_  / /_  /  /_ / /__/ /        ")
            print("     ___/ / /|  /_/ / / __/ / __/ /  __//  __  \        ")
            print("    /____/_/ |_// __//_/   /_/   /____//_/  /__/           ")
            print("-----------------------------------------------------------------")
            print(" Packet sniffing script implemented using scapy \n ")
            print("-----------------------------------------------------------------")
            print("1) SNIFF PACKETS")
            print("2) PORT SCANNING")
            print("3) LOAD SNIFFED PACKET")
            print("4) EXIT")
            option = int(input())
            if option == 1:
                self.sniff_packets()
                break
            elif option == 2:
                self.port_scan('SauceDemo.com', 20, 22, 'tcp')
                self.port_scan('SauceDemo.com', 20, 22, 'udp')
                self.port_scan('SauceDemo.com', 20, 21, 'ftp')
                self.port_scan('SauceDemo.com', 22, 22, 'ssh')
                self.port_scan('SauceDemo.com', 143, 143, 'imap')
                self.port_scan('SauceDemo.com', 5060, 5060, 'sip')
                break
            elif option == 3:
                self.load_sniffed_packets()
                break
            elif option == 4:
                exit(0)
            else:
                print("INVALID INPUT RETRY")

if __name__ == "__main__":
    scanner = PortScanner()
    scanner.menu()
