import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import time

from modules.IP2Earth import IP2Earth
from helpers import print_total_time

def main():
    """
    Main function to parse command-line arguments and execute the IP2Earth process.
    This script extracts IP addresses from a .pcap file, determines their approximate
    locations, and generates a KML file for visualization in Google Earth.
    """
    
    start_time = time.time()
    parser = ArgumentParser(prog='main.py', formatter_class=RawDescriptionHelpFormatter, description="Extracts IP addresses from a .pcap file, determines their approximate locations, and generates a KML file for visualization in Google Earth.", epilog="Examples:\n"
           "python main.py -p traffic.pcap\n"
           "python main.py -p traffic.pcap -o kml_file --protocol tcp --port 443,80\n"
           "\nIf the -o option is not specified, a default output filename will be generated and saved in the 'output' folder.")
    
    # Argument for the .pcap file
    parser.add_argument(
        "-p",
        "--pcap-file",
        help='Path to the .pcap/.pcapng file for extracting IP addresses. This option is not required if either -d or -l is specified.',
        metavar="<path>",
        required=False
    )

    # Argument for the .json data file containing IP address information
    parser.add_argument(
        "-d",
        "--data-file",
        help="Path to the .json file containing IP address data. The file must include 'timestamp', 'ip', and 'server_name' keys, but only the 'ip' value is mandatory.",
        required=False,
        metavar="<path>"
    )
    # Argument for the .json file containing geographic locations
    parser.add_argument(
        "-l",
        "--locations-file",
        help="Path to the .json file containing geographic locations. The file must include 'lat', 'lon', 'server_name', 'org', 'country' and 'city' keys, but only 'lat' and 'lon' values are mandatory.",
        required=False,
        metavar="<path>"
    )
    # Argument for specifying an optional output filename
    parser.add_argument(
        "-o",
        "--output-filename",
        help="Optional filename for all the files created in the process. If not provided, a default filename will be generated. (note: not filepath, all files will be created in a separate folders. You can change the default folders in 'constants.py')",
        metavar="<path>",
        required=False
    )
    # Argument for specifying the protocol(s) to filter by
    parser.add_argument(
        "--protocol",
        help="Specify the protocol(s) to filter by, separated by commas. Options include 'tcp' and 'udp'. Defaults to 'tcp'. Example: '--protocol tcp,udp'",
        required=False
    )
    # Argument for specifying a port to filter by
    parser.add_argument(
        "--port",
        help="Specify the port number(s) to filter by, separated by commas. If not specified, all ports are included. Example: '--port 80,443'",
        required=False
    )
    # Argument for using a generator to process large .pcap files
    parser.add_argument(
        "--use-generator",
        help='Utilize a Python generator to efficiently process large .pcap files.',
        action='store_true',
        required=False
    )
    # Argument for resolving IP addresses to obtain server names
    parser.add_argument(
        "--reverse-dns",
        help='Reverse DNS of the IP addresses to obtain server names (note: this may be very time-consuming).',
        action='store_true',
        required=False
    )

    
    # Display help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    # Validation: Ensure that --output-filename is used with one of the input options
    if args.output_filename and not (args.pcap_file or args.data_file or args.locations_file):
        parser.error("The --output-file option can only be used if one of --pcap-file, --data-file, or --locations-file is also specified.")
        
    # Validation: Ensure that at least one input file is specified
    if not (args.pcap_file or args.data_file or args.locations_file):
        parser.error("You must specify one of the following: --pcap-file, --data-file, or --locations-file")

    # Validation: Ensure that only one input file option is specified
    if (args.pcap_file and args.data_file) or (args.pcap_file and args.locations_file) or (args.data_file and args.locations_file):
        parser.error("You must specify only one of the following: --pcap-file, --data-file, or --locations-file")
    
    # Validation: Ensure that generator is only used with pcap file
    if args.use_generator and not args.pcap_file:
        parser.error("--use-generator can only be used with the -p (or --pcap-file) argument.")
        
    # Validation: Ensure that --use-generator, --protocol or --port is only used with a pcap file
    if (args.reverse_dns and not args.pcap_file) or (args.protocol and not args.pcap_file) or (args.port and not args.pcap_file):
        parser.error("Please specify the path of a pcap file using '-p <path>'.")
    
    
    
    
    success = IP2Earth(protocols=args.protocol,ports=args.port, use_gen=args.use_generator, reverse_dns=args.reverse_dns)\
        .run(
            pcap_path=args.pcap_file, 
            data_json_path=args.data_file, 
            locations_json_path=args.locations_file, 
            output_filename=args.output_filename
        )
    
        
    if not success:
        print("[-] IP2Earth failed.")
    
    print_total_time(start_time)

if __name__ == "__main__":
    main()

