import sys
import json
import time
import requests
from colorama import Style

from lib import *
from constants import DEFAULT_LOCATIONS_FOLDER, API_URL, API_END_URL, API_FIELDS, REVERSE_DNS, WARNING_COLOR, INFO_COLOR, SUCCESS_COLOR, ERROR_COLOR
from helpers import save_json_file, get_output_filepath, print_total_time, terminate_program
from modules.LoadingAnimation import LoadingAnimation

class Geofinder:
    """
    The Geofinder class is responsible for converting IP addresses into geographical locations using an external API.
    It processes a list of IP addresses, fetches their corresponding location data, and saves the results to a JSON file.
    
    Key Features:
    - Takes a list of IP addresses and their associated metadata (e.g., server name - if 'reverse_dns' is True, timestamp) and sends them to an API for geolocation.
    - Handles API rate limits by managing request counts and implementing timeouts when the maximum number of requests is reached.
    - Displays real-time progress through a loading animation, providing feedback on the number of IPs processed and API request status.
    - Saves the resulting location data to a specified output file, which can later be used for visualization or analysis.
    
    The class is part of a larger system that visualizes network traffic by mapping IP addresses to their geographical locations.
    This mapping allows users to see where network traffic is originating or terminating, making it easier to analyze the data.
    """
    def __init__(self, reverse_dns:bool):
        self.reverse_dns:bool = reverse_dns if reverse_dns else REVERSE_DNS  # If False (arg not used) check for the constant.py value
        self.location_data_filename:str = ""
        self.requests_remaining: int = 2 # Placeholder value, will be updated dynamically
        self.time_until_reset: int = 60 # Placeholder value, will be updated dynamically
        self.total_address_count: int = 0
        self.current_index: int = 0
        self.animation = LoadingAnimation()

    def run(self,data_list: List[Dict[str, Any]], output_filename: str) -> Optional[str]:
        """
        Main method to fetch and save location data.

        :param data_list: List of dictionaries containing IP, server name and timestamp.
        :param output_filename: Filename for the output JSON.
        :return: Filepath of json data file
        """
        print(INFO_COLOR,"[*] Running script...", Style.RESET_ALL)
        start_time = time.time()
        self.total_address_count = len(data_list)
        data = self.process_data_list(data_list)
        
        print(INFO_COLOR,"[*] Creating JSON file...", Style.RESET_ALL)
        output_filepath = get_output_filepath(ext='.json', folder=DEFAULT_LOCATIONS_FOLDER, filename=output_filename)
        success_data = [entry for entry in data if entry["status"] == "success"]
        if len(success_data) == 0:
            terminate_program("[-] Location file is empty.")
            
        ###
            
        if not save_json_file(filepath=output_filepath, data=success_data):
            terminate_program("[-] Failed to save location data file.")
            
        print_total_time(start_time, "Geofinder")
        return output_filepath

    def process_data_list(self, data_list:List[Dict[str,Any]]) -> List[Dict[str,Any]]:
        try:
            data: List[Dict[str, Any]] = []
            self.animation.start(current_count=0, total_count=self.total_address_count)
            timeout_count = 0
            for item in data_list:
                self.current_index += 1
                self.check_request_count()
                self.animation.update_progress(self.current_index, self.total_address_count)
                location_data = self.fetch_location_data(item, timeout_count)
                if location_data is not None:
                    data.append(location_data)
                else:
                    break
                
                time.sleep(0.1) # Delay in order to not get a timeout from ip-api from too many requests
            self.animation.stop()
            print(SUCCESS_COLOR,"[+] Location search complete.", Style.RESET_ALL)
            return data
        except KeyboardInterrupt:
            self.animation.stop()
            terminate_program(exit_code=0)
        except Exception as e:
            self.animation.stop()
            terminate_program(f"[-] Error getting data from the api endpoint. {str(e)}")
    
    def fetch_location_data(self, item: Dict[str, Any], timeout_count:int) -> Optional[Dict[str, Any]]:
        """
        Fetches location data for a single IP address from an external API.
        
        :param item: A dictionary containing an IP address, server name, and timestamp.
                     Example: {"ip": "191.0.2.1", "server_name": "example.com", "timestamp": 1622563200}
        :return: A dictionary containing the location data if the request is successful, or None if it fails.
        """
        if self.reverse_dns:
            api = f"{str(API_URL)}{item.get('ip', "ERROR")}{str(API_END_URL)}{str(API_FIELDS)},resolve"
        else:
            api = f"{str(API_URL)}{item.get('ip', "ERROR")}{str(API_END_URL)}{str(API_FIELDS)}"
        try:
            response = requests.get(api)
            req_code = response.status_code
            if int(req_code) == 200:
                self.time_until_reset = response.headers["X-Ttl"]
                self.requests_remaining = response.headers["X-Rl"]
                output_data = response.text
                output_data = json.loads(output_data)
                output_data["protocol"] = item.get("protocol", "ERROR")
                output_data["port"] = item.get("port", "ERROR")
                return output_data
                
            elif int(req_code) == 429:
                if timeout_count > 1:
                    terminate_program(f"[-] Fatal error. Maximum number of request reached. [Requests: {self.requests_remaining} | Time: {self.time_until_reset}]")
                timeout_count += 1
            else:
                terminate_program(f"[-] Error in ip-api request: {response.status_code}")
        except requests.RequestException as e:
            terminate_program(f"[-] Error during request: {str(e)}")
        except Exception as e:
            terminate_program(f"[-] An unexpected error occured: {str(e)}")

    def request_timeout(self) -> None:
        """
        Handles the timeout when the maximum number of API requests is reached.
        
        This method pauses the script and waits until the API rate limit resets, after which
        the script resumes fetching location data.
        """
        self.animation.stop()
        timeout = int(self.time_until_reset) + 2
        try:
            while timeout > 0:
                sys.stdout.flush()
                sys.stdout.write(f"\r {WARNING_COLOR}[!] Maximum number of requests reached. Waiting for {str(timeout).zfill(2)} seconds.{Style.RESET_ALL}\r")
                timeout -= 1
                time.sleep(1)
            
            print(SUCCESS_COLOR,f"\n [+] Script is running again.", Style.RESET_ALL)
            self.animation.start(current_count=self.current_index, total_count=self.total_address_count)
        except KeyboardInterrupt:
            self.animation.stop()
            terminate_program(exit_code=0)
    
    def check_request_count(self) -> None:
        """
        Checks the remaining number of API requests and handles a timeout if the limit is reached.
        
        This method monitors the number of API requests left and triggers a timeout period if the number
        of remaining requests drops to 1 or below, ensuring compliance with API rate limits.
        """
        if int(self.requests_remaining) <= 1:
            self.request_timeout()



    
