import time
import socket
import ipaddress
import json
import dpkt
from colorama import Style

from lib import *
from modules.LoadingAnimation import LoadingAnimation
from helpers import save_json_file, get_output_filepath, print_total_time, terminate_program, get_file_extension
from constants import DEFAULT_DATA_FOLDER, PCAP_PROCESSING_USE_GENERATOR, WARNING_COLOR, INFO_COLOR, SUCCESS_COLOR, ERROR_COLOR, PORT, PROTOCOL

class IPGrabber:
    """
    The IPGrabber class is designed to process pcap files by extracting IP addresses from network packets.
    
    Key Features:
    - Extracts IP addresses from pcap files using either a list-based or generator-based approach, depending on the user's preference.
    - Sends the extracted IP addresses to another class responsible for converting them into geographical locations using an API.
    - The geographical locations are then saved to a KML file, which can be displayed on Google Earth for visual representation.
    - Supports optional IP address resolution to hostnames, though this may be time-consuming.
    - Utilizes a loading animation to indicate progress during packet processing.
    - Automatically counts the total number of packets in the pcap file before processing begins.
    
    The class is part of a larger system designed to visualize the geographical locations of IP addresses captured in network traffic,
    providing an intuitive way to analyze the data using tools like Google Earth.
    """
    
    def __init__(self, protocols:Optional[str] = PROTOCOL, ports:Optional[Set[int]] = PORT):
        """
        Initializes the IPGrabber class with optional protocol and port filtering.

        Args:
            protocols (Set[str], optional): Set of protocols to filter by. Defaults to an empty set.
            ports (Set[int], optional): Set of ports to filter by. Defaults to an empty set.
        """
        self.protocols:List[str] = protocols.lower().split(',') if protocols else ['tcp']
        self.port = set(map(int, ports.split(','))) if ports else set()

        self.data_json_filename:str = ""
        self.current_packet_count:int = 0
        self.animation = LoadingAnimation()
        self.total_packet_count:int = 100 # Random number to avoid division by 0
        self.data_list: List[Dict[str, Any]] = []
        
    def run(self, pcap_filepath: str, output_filename:str, use_gen:bool) -> str:
        """
        Main method to process a pcap file and save data.

        Args:
            pcap_filepath (str): Path to the pcap file.
            output_filename (str): Name of the output JSON file.
            use_gen (bool): Whether to use a generator for processing pcap files.

        Returns:
            bool: True if successful, False otherwise.
        """

        use_gen = use_gen if use_gen else PCAP_PROCESSING_USE_GENERATOR # If False (arg not used) check for the constant.py value
        start_time = time.time()
        print(INFO_COLOR,"[*] Counting packets...", Style.RESET_ALL)
        self.total_packet_count = self.count_pcap_rows(pcap_filepath)

        if use_gen:
            output_filepath = self.save_to_json_gen(pcap_filepath, output_filename)
        else:
            output_filepath = self.save_to_json(pcap_filepath, output_filename)
         
        if not output_filepath:
            terminate_program(f"[-] Failed to save data file.")
        print_total_time(start_time, 'IPGrabber (Generator)') if use_gen else print_total_time(start_time, 'IPGrabber')
        return output_filepath

 
    ####################################################################################
    #                             Default processing                                   #
    ####################################################################################
    
    def save_to_json(self, pcap_filepath:str, output_filename:str) -> Optional[str]:
        """
        Saves pcap data to a JSON file using a list.

        Args:
            pcap_filepath (str): Path to the pcap file.
            output_filename (str): Name of the output JSON file.

        Returns:
            bool: True if successful, False otherwise.
        """
        output_filepath = get_output_filepath(
            ext=".json",
            folder=DEFAULT_DATA_FOLDER,
            filename=output_filename,
        )
        data_list = self.process_pcap_file(pcap_filepath)
        if save_json_file(filepath=output_filepath, data=data_list):
            return output_filepath
        return None
        
    def process_pcap_file(self, pcap_filepath: str,) -> List[Dict[str, Any]]:
        """
        Processes a pcap file and returns a list of packet data.

        Args:
            pcap_filepath (str): Path to the pcap file.

        Returns:
            list: List of packet data dictionaries.
        """
        data_list: List[Dict[str, Any]] = []
        try:
            with open(pcap_filepath, 'rb') as f:
                pcap = dpkt.pcap.UniversalReader(f)
                self.process_pcap_packets(pcap, data_list)
            return data_list
        except PermissionError:
            terminate_program(f"[-] Perimssion denied: Unable to read {pcap_filepath}")                 
        except FileNotFoundError:
            terminate_program(f"Error: The file '{pcap_filepath}' was not found.")
        except Exception as e:
            terminate_program(f"[-] Error in packet processing: {str(e)}")
            
        

    
    def process_pcap_packets(self, pcap:dpkt.pcap.UniversalReader, data_list: List[Dict[str, Any]]) -> None:
        """
        Processes packets from a pcap file and appends data to a list.

        Args:
            pcap (dpkt.pcap.UniversalReader): Reader object for the pcap file.
            data_list (List[Dict[str, Any]]): List to append packet data.

        Returns:
            None
        """           
        try:
            print(INFO_COLOR,"[*] Processing packets...", Style.RESET_ALL)
            self.animation.start(current_count=0, total_count=self.total_packet_count)
            seen_ips: Set[str] = set()

            for timestamp, buf in pcap:
                self.handle_packet(buf, timestamp, seen_ips, data_list)
                     
        except KeyboardInterrupt:
            self.animation.stop()
            terminate_program(exit_code=0)
  
        except Exception as e:
            self.animation.stop()
            terminate_program(message=f"\n[-] An unexpected error occured while extracting pcap data: {str(e)}",exit_code=1)

        self.animation.stop() 
        print(SUCCESS_COLOR,"[+] Packets processes successfully.", Style.RESET_ALL)
    
    def handle_packet(self, buf: bytes, timestamp: float, seen_ips: Set[str], data_list:List[Dict[str, Any]]) -> None:
        """
        Handles a single packet and adds its information to the data list.

        Args:
            buf (bytes): Packet buffer.
            timestamp (float): Packet timestamp.
            seen_ips (Set[str]): Set of IPs already seen.
            data_list (List[Dict[str, Any]]): List to append packet data.

        Returns:
            None
        """
        eth = dpkt.ethernet.Ethernet(buf)
        self.current_packet_count += 1
        self.animation.update_progress(self.current_packet_count, self.total_packet_count)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP) and 'tcp' in self.protocols:
                tcp = ip.data
                if not self.port or tcp.sport in self.port or tcp.dport in self.port:
                    port = tcp.sport if tcp.sport in self.port else tcp.dport
                    result = self.extract_packet_info(ip, timestamp, seen_ips, str(port), protocol='TCP')
                    if result:
                        data_list.extend(result)
            elif isinstance(ip.data, dpkt.udp.UDP) and 'udp' in self.protocols:
                udp = ip.data
                if not self.port or udp.sport in self.port or udp.dport in self.port:
                    port = udp.sport if udp.sport in self.port else udp.dport
                    result = self.extract_packet_info(ip, timestamp, seen_ips, str(port), protocol='UDP')
                    if result:
                        data_list.extend(result)


    ####################################################################################
    #                             Generator processing                                 #
    ####################################################################################

    def save_to_json_gen(self, pcap_filepath:str, output_filename:str) -> Optional[str]:
        """
        Saves packet data from a pcap file to a JSON file using a generator.

        This function processes the pcap file and writes the extracted packet data
        to a JSON file. The data is written incrementally using a generator to handle
        large files efficiently.

        Args:
            pcap_filepath (str): Path to the pcap file to be processed.
            output_filename (str): Desired name of the output JSON file.

        Returns:
            bool: True if the data was successfully saved, False otherwise.
        """
        output_filepath = get_output_filepath(ext=".json",folder=DEFAULT_DATA_FOLDER,filename=output_filename)
        if self.write_to_json_gen(pcap_filepath, output_filepath):
            return output_filepath
        return None

    def write_to_json_gen(self, pcap_filepath:str, output_filepath:str) -> bool:
        """
        Writes packet data to a JSON file using a generator.

        This function reads packet data from a pcap file using a generator,
        and writes it to a JSON file. The function ensures that the data is
        written in JSON array format.

        Args:
            pcap_filepath (str): Path to the pcap file to be processed.
            output_filepath (str): Path to the output JSON file.

        Returns:
            bool: True if the data was successfully written, False otherwise.
        """
        try:
            with open(output_filepath, 'w') as json_file:
                json_file.write('[\n')
                first = True
                processed_pcap = self.process_pcap_file_gen(pcap_filepath) 
                  
                for data in processed_pcap:
                    if not first:
                        json_file.write(',\n')
                    json.dump(data, json_file)
                    first = False
                json_file.write('\n]')
                
            print(SUCCESS_COLOR,f"[+] Data saved successfully to {output_filepath}", Style.RESET_ALL)  
            return True
        except PermissionError:
            terminate_program(f"[-] Perimssion denied: Unable to write to {output_filepath}")
        except Exception as e:
            terminate_program(f"[-] Error writing to json file: {e}")


    def process_pcap_file_gen(self, pcap_filepath:str) -> Generator[List[Dict[str, Any]], None, None]:
        """
        Processes a pcap file and yields packet data using a generator.

        This function opens the specified pcap file and processes its contents
        using a generator. It yields processed packet data incrementally, which
        allows for handling large files without consuming too much memory.

        Args:
            pcap_file_path (str): Path to the pcap file to be processed.

        Yields:
            list: List of packet data dictionaries.
        """
        try:
            print(INFO_COLOR,"[*] Opening file...", Style.RESET_ALL)
            with open(pcap_filepath, 'rb') as f:
                pcap = dpkt.pcap.UniversalReader(f)
                yield from self.process_pcap_packets_gen(pcap)

        except PermissionError:
            terminate_program(f"[-] Perimssion denied: Unable to read {pcap_filepath}", 1)   
        except FileNotFoundError:
            terminate_program(f"[-] File not found: '{pcap_filepath}", 1)
        except Exception as e:
            terminate_program(f"[-] An unexpected error occured while processing packets using generator: {str(e)}")

    def process_pcap_packets_gen(self, pcap:dpkt.pcap.UniversalReader) -> Generator[List[Dict[str, Any]], None, None]:
        """
        Processes packets from a pcap file and yields them as a generator.

        This function processes each packet in the provided pcap reader object,
        extracting relevant data and yielding it as a list of dictionaries. The use
        of a generator allows for processing large pcap files efficiently.

        Args:
            pcap (dpkt.pcap.UniversalReader): Reader object for the pcap file.

        Yields:
            list: List of packet data dictionaries.
        """
        try:
            print(INFO_COLOR,"[*] Processing packets...", Style.RESET_ALL)
            self.animation.start(current_count=0, total_count=self.total_packet_count)
            seen_ips = set()
            for timestamp, buf in pcap:
                yield from self.handle_packet_gen(buf, timestamp, seen_ips)
        
        except KeyboardInterrupt:
            self.animation.stop()
            terminate_program(exit_code=0)
  
        except Exception as e:
            self.animation.stop()
            terminate_program(message=f"\n[-] An unexpected error occured while extracting pcap data: {str(e)}",exit_code=1)

        self.animation.stop() 
        print(SUCCESS_COLOR,"[+] Packets processes successfully.", Style.RESET_ALL)

    def handle_packet_gen(self, buf: bytes, timestamp:float, seen_ips:Set[str]) -> Generator[List[Dict[str, Any]], None, None]:
        """
        Handles a single packet and adds its information to the data list.

        Args:
            buf (bytes): Packet buffer.
            timestamp (float): Packet timestamp.
            seen_ips (Set[str]): Set of IPs already seen.
            data_list (List[Dict[str, Any]]): List to append packet data.

        Yields:
            list: List of packet data dictionaries.
        """
        eth = dpkt.ethernet.Ethernet(buf)
        self.current_packet_count += 1
        self.animation.update_progress(self.current_packet_count, self.total_packet_count)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP) and 'tcp' in self.protocols:
                tcp = ip.data
                if not self.port or tcp.sport in self.port or tcp.dport in self.port:
                    port = tcp.sport if tcp.sport in self.port else tcp.dport
                    results = self.extract_packet_info(ip, timestamp, seen_ips, str(port), protocol='TCP')
                    if results:
                        for result in results:
                            yield result
            if isinstance(ip.data, dpkt.udp.UDP) and 'udp' in self.protocols:
                udp = ip.data
                if not self.port or udp.sport in self.port or udp.dport in self.port:
                    port = udp.sport if udp.sport in self.port else udp.dport
                    results = self.extract_packet_info(ip, timestamp, seen_ips, str(port), protocol='UDP')
                    if results:
                        for result in results:
                            yield result

    def extract_packet_info(self, ip: dpkt.ip.IP, timestamp:float, seen_ips: Set[str], port:str, protocol:str) -> List[Dict[str, Any]]:
        """
        Extracts information from an IP packet.

        Args:
            ip (dpkt.ip.IP): IP packet object.
            timestamp (float): Packet timestamp.
            seen_ips (Set[str]): Set of seen IP addresses.
            port (str, optional): Port number. Defaults to None.
            protocol (str, optional): Protocol type. Defaults to 'TCP'.

        Returns:
            list: List of dictionaries containing packet information.
        """
        data_list: List[Dict[str, Any]] = []
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        def add_row(ip_address:str):
            if ip_address not in seen_ips and self.is_valid_ip(ip_address):
                seen_ips.add(ip_address)
                data_list.append(
                    {
                        "timestamp": int(timestamp),
                        "ip": ip_address,
                        "protocol": protocol,
                        "port": port
                    }
                )

        add_row(src_ip)
        add_row(dst_ip)
        return data_list 

    def is_valid_ip(self, ip_address:str) -> bool:
        """
        Validates whether an IP address is public and non-reserved.

        This method checks if the provided IP address is not part of the 
        following reserved ranges:
        - Private IP ranges
        - Loopback addresses
        - Multicast addresses
        - Link-local addresses

        Args:
            ip_address (str): The IP address to validate.

        Returns:
            bool: True if the IP address is public and not reserved, False otherwise.
        """
        ip = ipaddress.ip_address(ip_address)
        return not any([
            ip.is_private, 
            ip.is_loopback, 
            ip.is_multicast,
            ip.is_link_local
        ])

    def count_pcap_rows(self, pcap_filepath: str) -> int:
        """
        Counts the number of rows (packets) in a pcap file.

        :param pcap: dpkt.pcap.UniversalReader or dpkt.pcapng.Reader object.
        :return: Number of rows if successful, -1 if there is an error.
        """
        
        try:
            with open(pcap_filepath, 'rb') as f:
                pcap = dpkt.pcap.UniversalReader(f)
                row_count = 0
                for _ in pcap:
                    row_count += 1
                
                if row_count <= 0:
                    terminate_program(f"[-] Empty file: {pcap_filepath}")
                
                return row_count

        except PermissionError:
            terminate_program(f"[-] Perimssion denied: Unable to read {pcap_filepath}")                 
        except FileNotFoundError:
            terminate_program(f"Error: The file '{pcap_filepath}' was not found.")
        except Exception as e:
            terminate_program(f"[-] Error in packet processing: {str(e)}")
        
