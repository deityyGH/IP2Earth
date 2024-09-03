import json
import xml.etree.ElementTree as ET
import time
import sys
from colorama import Style

from lib import *
from helpers import get_output_filepath, print_total_time, terminate_program
from constants import DEFAULT_KML_FOLDER, INFO_COLOR, SUCCESS_COLOR, WARNING_COLOR

class KMLCreator:
    """
    KMLCreator is a utility class to convert location data from a JSON file into a KML file.
    The KML format is used for displaying geographic data in like Google Earth.
    """
    
    def run(self, locations_path:str, output_filename:str) -> bool:
        """
        Executes the process of reading JSON data, converting it to KML, and saving the KML file.

        :param json_filepath: Path to the JSON file containing location data.
        :param output_filename: Desired name for the output KML file.
        :return: True if the process completes successfully, False otherwise.
        """
        start_time = time.time()
        
        locations_data = self.open_json(locations_path)
        if not locations_data:
            return False
        
        kml_file_string = self.generate_kml_content(locations_data)
        if not kml_file_string:
            return False
        
        if self.save_kml(kml_file_string, output_filename):
            print_total_time(start_time, "KMLCreator")
            return True
        return False

    
    def open_json(self, filepath:str) -> List[Dict[str, Any]]:
        """
        Opens and parses a JSON file.

        :param filepath: Path to the JSON file.
        :return: List of dictionaries containing the JSON data.
        """
        try:
            print(INFO_COLOR,"[*] Opening JSON file...", Style.RESET_ALL)
            with open(filepath, "r") as file:
                data = json.load(file)
                print(SUCCESS_COLOR,"[+] JSON file loaded successfully.", Style.RESET_ALL)
                return data
        except PermissionError:
            terminate_program(f"[-] Perimssion denied: Unable to read {filepath}")
        except FileNotFoundError:
            terminate_program("[-] The specified JSON file was not found.")
        except json.JSONDecodeError:
            terminate_program("[-] The JSON file contains invalid data.")
        except Exception as e:
            terminate_program(f"[-] An unexpected error occurred: {e}")

    def generate_kml_content(self, json_data:List[Dict[str, Any]]) -> str:
        """
        Converts location data from JSON format into a KML format.

        :param json_data: List of dictionaries containing location information.
        :return: A string with KML-formatted content.
        """
        try:
            kml = ET.Element('kml', xmlns='http://www.opengis.net/kml/2.2')
            document = ET.SubElement(kml, 'Document')
            for item in json_data:
                lat = item.get('lat', None)
                lon = item.get('lon', None)
                if lat is None or lon is None:
                    print(WARNING_COLOR, f"[!] Skipping item with missing lat/lon: {item}\n", Style.RESET_ALL)
                    continue
                placemark = ET.SubElement(document, 'Placemark')
                
                name = ET.SubElement(placemark, 'name')
                name.text = f"{item.get('city', 'CITY')} | {item.get('country', 'COUNTRY')} | {item.get('org', 'ORG')}"
                
                description = ET.SubElement(placemark, 'description')
                description.text = f"{item.get('query', 'IP')} | {item.get('reverse', "")}"
                
                point = ET.SubElement(placemark, 'Point')
                coords = ET.SubElement(point, 'coordinates')
                
                coords.text = f"{float(lon):.8f},{float(lat):.8f},0"

            kml_content = ET.tostring(kml, encoding='utf-8', method='xml').decode('utf-8')
            return f'<?xml version="1.0" encoding="UTF-8"?>\n{kml_content}'

        except KeyboardInterrupt:
            terminate_program(exit_code=0)
        except Exception as e:
            terminate_program(f"[-] Error creating kml file string. {str(e)}")

    
    def save_kml(self, kml_content:str, output_filename:str) -> bool:
        """
        Saves the generated KML string to a file.

        :param kml_content: The KML file content as a string.
        :param output_path: The file path where the KML file should be saved.
        :return str: KML output filepath string.
        """
        
        try:
            output_filepath = get_output_filepath(ext='.kml', folder=DEFAULT_KML_FOLDER, filename=output_filename) 
            with open(output_filepath, "w") as f:
                f.write(kml_content)
            print(SUCCESS_COLOR,f"[+] File saved successfully to {output_filepath}", Style.RESET_ALL)
            return True
        except PermissionError:
            terminate_program(f"[-] Perimssion denied: Unable to write to {output_filepath}")
        except Exception as e:
            terminate_program(f"[-] Error saving KML file: {str(e)}")

    

    
    


    

