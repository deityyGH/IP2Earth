import os
import json
from colorama import Style
import time

from lib import *
from modules.IPGrabber import IPGrabber
from modules.Geofinder import Geofinder
from modules.KMLCreator import KMLCreator
from helpers import ip2earth_logo, terminate_program, print_total_time
from constants import DEFAULT_DATA_FILENAME, DEFAULT_KML_FILENAME, DEFAULT_LOCATIONS_FILENAME, PROTOCOL, PORT, INFO_COLOR, SUCCESS_COLOR, SAVE_ALL


class IP2Earth:
    """
    IP2Earth is a tool that processes network capture files (.pcap) to extract IP addresses,
    resolve them to geographical locations, and create KML files for visualization in Google Earth.
    """
    
    def __init__(self, use_gen:bool, reverse_dns:bool, protocols:Optional[str] = PROTOCOL, ports:Optional[str] = PORT):
        self.use_gen = use_gen
        self.reverse_dns = reverse_dns
        self.ports = ports
        self.protocols = protocols

    
    def run(self, pcap_path: Optional[str] = None, data_json_path: Optional[str] = None,locations_json_path: Optional[str] = None, output_filename:Optional[str] = None) -> bool:
        """
        Main entry point for processing files based on priority: .pcap -> data.json -> locations.json.

        :param use_gen: Flag to control generalization of data.
        :param reverse_dns: Flag to control whether IP resolution should be attempted.
        :param pcap_path: Path to captured .pcap file (highest priority).
        :param data_json_path: Path to .json data file (second priority).
        :param locations_json_path: Path to .json locations file (third priority).
        :param output_filename: Desired name for the output KML file. Defaults to a predefined filename based on file type.
        :return: True if the process completes successfully, False otherwise.
        """
        
        ip2earth_logo()
        try:
            if pcap_path is not None:
                output_filename = output_filename or DEFAULT_DATA_FILENAME
                return self.process_pcap(pcap_path, output_filename)
            elif data_json_path is not None:
                output_filename = output_filename or DEFAULT_LOCATIONS_FILENAME
                return self.process_data_json(data_json_path, output_filename)
            elif locations_json_path is not None:
                output_filename = output_filename or DEFAULT_KML_FILENAME
                return self.process_locations_json(locations_json_path, output_filename)
        except KeyboardInterrupt:
            terminate_program(exit_code=0)
        except Exception as e:
            terminate_program(f"An unexpected error ocurred: {str(e)}")
        
    
    def process_pcap(self, pcap_path:str, output_filename:str) -> bool:
        data_filepath = self.run_ipgrabber(pcap_path, output_filename)
        if not data_filepath:
            terminate_program(f"File: {data_filepath} not found.")

        ip_data  = self.load_json_file(data_filepath)
        if not ip_data:
            terminate_program(f"File: {ip_data} not found.")
        
        locations_filepath = self.run_geofinder(ip_data, output_filename)
        if not locations_filepath:
            terminate_program(f"File: {locations_filepath} not found.")

        return self.run_kmlcreator(locations_filepath, output_filename)
    
    def run_ipgrabber(self, pcap_filepath: str,output_filename:str) -> str:
        """
        Extract IP addresses from a .pcap file and save them to a .json file.

        :param pcap_path: Path to the .pcap file.
        :param output_filename: Name for the output .json file.
        :return: Path to the generated .json file, or None if the operation fails.
        """
        if not self.validate_filepath(pcap_filepath):
            terminate_program(f"[-] File not found: {pcap_filepath}.")

        ip_grabber = IPGrabber(protocols=self.protocols, ports=self.ports)
        result_filepath = ip_grabber.run(pcap_filepath=pcap_filepath, output_filename=output_filename, use_gen=self.use_gen)

        if result_filepath:
            return result_filepath
        terminate_program('[-] IPGrabber failed to process the .pcap file.', 1)

    def load_json_file(self, filepath: str) -> Optional[List[Dict[str, Any]]]:
        """
        Load and parse a JSON file.

        :param filepath: Path to the JSON file.
        :return: List of dictionaries containing the parsed JSON data.
        """
        err_msg = ""
        if not self.validate_filepath(filepath):
            terminate_program(f"[-] File not found: {filepath}.")
        try:
            print(INFO_COLOR,f"[*] Loading JSON file: {filepath}...", Style.RESET_ALL)
            with open(filepath, "r") as file:
                data = json.load(file)
            print(SUCCESS_COLOR,"[+] JSON file loaded successfully.", Style.RESET_ALL)
            return data
        except json.JSONDecodeError as e:
            err_msg = f"[-] JSON decoding error in file {filepath}: {str(e)}"
        except Exception as e:
            err_msg = f"[-] Unexpected error while loading file {filepath}: {str(e)}"     
        terminate_program(err_msg)


    def run_geofinder(self, ip_data:List[Dict[str,Any]], output_filename:str) -> Optional[str]:
        """
        Resolve IP addresses to geographic locations and save the results to a .json file.

        :param ip_data: List of dictionaries containing IP address information.
        :param output_filename: Name for the output .json file.
        :return: Path to the generated .json file, or None if the operation fails.
        """

        if not ip_data:
            terminate_program("[-] No IP data available for geolocation.")
        
        geofinder = Geofinder(reverse_dns=self.reverse_dns)
        result_filepath = geofinder.run(ip_data, output_filename=output_filename)
        if result_filepath is not None:
            return result_filepath
        terminate_program('[-] Geofinder failed to reverse DNS the IP addresses.', 1)
                


        
    def run_kmlcreator(self, locations_path:str, kml_output_path:Optional[str] = None) -> bool:
        """
        Convert location data from a .json file into a KML file.

        :param locations_filepath: Path to the .json file containing location data.
        :param output_filename: Desired name for the output .kml file.
        :return: True if the KML file was created successfully, False otherwise.
        """
        kmlcreator = KMLCreator()
        return kmlcreator.run(locations_path, kml_output_path)
    
       
    

    def process_data_json(self, data_json_path:str, output_filename:str) -> bool:
        """
        Complete process to handle a data .json file: resolve locations and create a KML file.

        :param data_json_path: Path to the .json file containing IP address data.
        :param output_filename: Name for the final output files.
        :return: True if the process completes successfully, False otherwise.
        """
        ip_data = self.load_json_file(data_json_path)
        if not ip_data:
            terminate_program('[-] IP file not found.')
        
        locations_filepath = self.run_geofinder(ip_data , output_filename)
        if not locations_filepath:
            terminate_program('[-] Location file not found.')
    
        return self.run_kmlcreator(locations_filepath, output_filename)

    
    def process_locations_json(self, locations_json_path:str, output_filename:str) -> bool:
        """
        Create a KML file from an existing locations .json file.

        :param locations_json_path: Path to the .json file containing location data.
        :param output_filename: Name for the final output KML file.
        :return: True if the KML file was created successfully, False otherwise.
        """
        
        locations_data  = self.load_json_file(locations_json_path)
        if not locations_data:
            terminate_program('[-] Location file not found.')
        
        return self.run_kmlcreator(locations_json_path, output_filename)

    
    
    def validate_filepath(self, filepath:str) -> bool:
        """
        Validate if the provided file path exists.

        :param filepath: Path to the file to be validated.
        :return: True if the file exists, False otherwise.
        """
        if not os.path.exists(filepath):
            return False
        
        if not os.path.isfile(filepath):
            return False
        return True
