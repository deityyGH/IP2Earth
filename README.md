# IP Geolocation Extractor and Visualizer
This Python program extracts IP addresses from '.pcap' or '.pcapng' file formats, determines their approximate geographic locations, and generates a KML file for visualization in Google Earth.

## Features
- **IP Address Extraction**: Extracts all public IP addresses from a provided `.pcap` or `.pcapng` file.
- **Geolocation Lookup**: Sends API requests to the ip-api.com service to determine the approximate geographic locations of the extracted IP addresses.
- **Google Earth Visualization**: Generates a KML file that can be uploaded to Google Earth, allowing for a visual representation of the IP addresses' locations.

## Requirements
- Python 3.x
- [dpkt](https://pypi.org/project/dpkt/)
- [colorama](https://pypi.org/project/colorama/)

You can install the required package using pip:
`pip install dpkt colorama`

## Usage
1. ### Clone repository:
   - `git clone https://github.com/deityyGH/IP2Earth.git`
   - `cd IP2Earth`
     
2. ### Start the program:
    - You can view the available options and usage instructions with:
       - `python main.py --help`
    - To process a .pcap or .pcapng file and generate a KML file, use:
       - `python main.py -p capture.pcap`
   (Note: use `python3` if using linux.)

3. ### Process the file:
    The program will extract all public IP addresses from the pcap file and send them to the ip-api.com service to retrieve their approximate locations.

4. ### Generate KML File:
    After obtaining the locations, the program generates a KML file that can be uploaded to Google Earth for visualization.

5. ### Upload KML file to Google Earth:
    1. Open [Google Earth](https://earth.google.com/)
    2. Click on **New**
    3. Select **Local KML file**
    4. Select **Import**
    5. Upload the file

## Example Commands
- Process a `.pcap` file:
   - `python main.py -p capture.pcap`
- Use JSON file with IP data:
   - `python main.py -d data.json`
- Use JSON file with location data:
   - `python main.py -l data.json`
- Specify more arguments:
   - `python main.py -p capture.pcapng --protocol tcp --port 443,80 --use-generator```


After running the above command, a KML file will be created in the current directory, which you can then upload to Google Earth to visualize the locations of the IP addresses.

## Notes
- The program only processes public IP addresses; private IP addresses are ignored.
- The geolocation results are approximate and may not represent exact locations.
- You may adjust some options in the constant.py file.
