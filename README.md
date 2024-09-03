# IP Geolocation Extractor and Visualizer
This Python program extracts IP addresses from '.pcap' or '.pcapng' file formats, determines their approximate geographic locations, and generates a KML file for visualization in Google Earth.

## Features
- IP Address Extraction: Extracts all public IP addresses from a provided .pcap file.
- Geolocation Lookup: Sends API requests to the ip-api.com service to determine the approximate geographic locations of the extracted IP addresses.
- Google Earth Visualization: Generates a KML file that can be uploaded to Google Earth, allowing for a visual representation of the IP addresses' locations.

## Requirements
- Python 3.x
- [dpkt](https://pypi.org/project/dpkt/)
- [colorama](https://pypi.org/project/colorama/)

You can install the required package using pip:
```pip install dpkt colorama```

## Usage
1. ### Load the file:
    To use the program, load your `.pcap` or `.json` file.
    - `python main.py -h | --help`
    - `python main.py -p <pcap_filepath> [-o <output_kml_filepath]`
    - `python main.py -d <data_filepath> [-o <output_kml_filepath]`
    - `python main.py -l <locations_filepath> [-o <output_kml_filepath]`

- Use either `-p`, `-d`, `-l`
- Optional path for the output .kml file. If not provided, a default filename will be generated. 

2. ### Process the file:
    The program will extract all public IP addresses from the .pcap file and send them to the ip-api.com service to retrieve their approximate locations.

3. ### Generate KML File:
    After obtaining the locations, the program generates a KML file that can be uploaded to Google Earth for visualization.

4. ### Upload KML file to Google Earth:
    1. [Google Earth](https://earth.google.com/)
    2. New
    3. Local KML file
    4. Import
    5. Upload the file

## Example
- `python main.py -p capture.pcap -o output.kml`
- `python main.py -d ip_data.json -o output.kml`
- `python main.py -l locations.json -o output.kml`

After running the above command, a KML file will be created in the current directory, which you can then upload to Google Earth to visualize the locations of the IP addresses.

## Notes
- The program only processes public IP addresses; private IP addresses are ignored.
- The geolocation results are approximate and may not represent exact locations.
