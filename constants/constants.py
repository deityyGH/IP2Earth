from typing import Optional, Set
from pathlib import Path
from colorama import Fore, Style
# API URL and Fields Configuration
# The 'lon' and 'lat' fields are mandatory for the API response.
# For detailed information on all available fields, refer to the official documentation:
# https://ip-api.com/docs/api:json
API_URL:str = 'http://ip-api.com/json/'
API_END_URL: str ='?fields='
API_FIELDS:str = 'status,message,country,region,regionName,city,lat,lon,org,as,query'

# Default Output Folders
# These are used if a full path is not specified by the user.
BASE_OUTPUT_DIR = Path('output')
DEFAULT_DATA_FOLDER:str = BASE_OUTPUT_DIR / 'ip_data'
DEFAULT_LOCATIONS_FOLDER:str = BASE_OUTPUT_DIR / 'location_data'
DEFAULT_KML_FOLDER:str = BASE_OUTPUT_DIR / 'kml_data'

# Default Output Filenames
# These are used if a filename is not specified by the user.
DEFAULT_DATA_FILENAME:str = 'new_file'
DEFAULT_LOCATIONS_FILENAME:str = 'new_file'
DEFAULT_KML_FILENAME:str = 'new_file'

SAVE_ALL = False


# Default Input Folders for Arguments '-p', '-d', or '-l'
# If set, only a filename is needed; the full path is not required.
DEFAULT_PCAP_INPUT_FOLDER:str = ''
DEFAULT_DATA_INPUT_FOLDER:str = ''
DEFAULT_LOCATIONS_INPUT_FOLDER:str = ''

# Configuration Flags
# If True, PCAP processing will utilize a generator for efficiency.
PCAP_PROCESSING_USE_GENERATOR:bool = False

# IP Resolution Flag
# If set to True, IP addresses will be resolved to geographical locations.
# This process can be very time-consuming and is therefore not recommended.
REVERSE_DNS:bool = False

# Filtering packets
PROTOCOL:str = 'tcp'
PORT:Optional[str] = None # None = All ports

# Colors for terminal output
INFO_COLOR = Fore.CYAN
SUCCESS_COLOR = Fore.GREEN
ERROR_COLOR = Fore.RED
WARNING_COLOR = Fore.YELLOW