import json
import time
from pathlib import Path
from colorama import Style
import sys

from lib import *
from constants import INFO_COLOR, SUCCESS_COLOR, ERROR_COLOR, WARNING_COLOR

def ip2earth_logo():
    print("""\
.____________________  ___________              __  .__     
|   \\_____   \\_____  \\ \\_   _____/____ ________/  |_|  |__  
|   ||    ___//  ____/  |    __)_\\__  \\\\_  __ \\   __\\  |  \\ 
|   ||   |   /       \\  |        \\/ __ \\|  | \\/|  | |   Y  \\
|___||___|   \\_______ \\/_______  (____  /__|   |__| |___|  /
                     \\/        \\/     \\/                 \\/ 
""")

def print_total_time(start_time:float, prog:Optional[str] = None) -> None:
    """
    Prints the total time taken since `start_time`.

    :param start_time: The start time to calculate elapsed time from.
    :param prog: Optional program name to include in the output.
    """
    total_time = time.time() - start_time
    if prog is None:
        print(INFO_COLOR,f"[*] Total time: {total_time:.2f} seconds.", Style.RESET_ALL)
    else:
        print(INFO_COLOR,f"[*] {prog} total time: {total_time:.2f} seconds.", Style.RESET_ALL)
    print("===============================================================")

def get_file_extension(file_path):
    path = Path(file_path)
    return path.suffix

def get_output_filepath(
    ext: str,
    folder: Optional[str] = None,
    filename: Optional[str] = None,
    filepath: Optional[str] = None,
    additional_text: str = "",
) -> str:
    """
    Generates a file path for saving output.

    :param ext: File extension (e.g., '.json', '.txt').
    :param folder: Optional folder path. Defaults to the script's directory.
    :param filename: Optional filename. Defaults to 'new_file'.
    :param filepath: Optional full file path. Overrides folder and filename if provided.
    :param additional_text: Text to append to the filename before the extension.
    :return: Full path to the output file as a string.
    """
    try:
        
        if not ext.startswith("."):
            ext = f".{ext}"

        if filepath is not None:
            path = Path(filepath)
            if path.suffix != ext:
                path = path.with_suffix(ext)
        else:
            # Set the folder path, defaulting to the script's directory.
            script_dir:Path = Path(__file__).parent
            folder:Path = Path(folder) if folder else script_dir
            folder.mkdir(parents=True, exist_ok=True)

            # Set the filename, defaulting to 'new_file'.
            filename = Path(filename).stem if filename else "new_file"

            if additional_text:
                filename = f"{filename}{additional_text}"

            path: Path = folder / (filename + ext)

        # Handle file name conflicts by appending a counter.
        counter = 1
        original_filename = Path(path).stem
        while path.exists():
            filename = f"{original_filename}({counter})"
            path = folder / (filename + ext) if folder else Path(filename + ext)
            counter += 1
            
        return str(path)
    except Exception as e:
        # Fallback to a random filename on error.
        print(ERROR_COLOR,f"[-] Error creating output filepath: {str(e)}", Style.RESET_ALL)
        if not ext.startswith("."):
            ext = f".{ext}"
        
        print(INFO_COLOR,f"[*] Generating random filename... {random_filename}", Style.RESET_ALL)
        random_filename = f"{str(int(time.time() * 1000))}{ext}"
        return random_filename


def save_json_file(filepath: str, data: List[Dict[str, Any]]) -> bool:
    """
    Saves a list of dictionaries as a JSON file.

    :param filepath: Path where the JSON file should be saved.
    :param data: List of dictionaries to save in the JSON file.
    :return: True if the file was saved successfully, False otherwise.
    """
    if len(data) == 0:
        return False
    try:
        print(INFO_COLOR,"[*] Saving JSON file...", Style.RESET_ALL)
        with open(filepath, "w") as file:
            json.dump(data, file, indent=4)
        print(SUCCESS_COLOR,f"[+] File saved successfully to {filepath}", Style.RESET_ALL)
        return True
    except PermissionError:
        print(ERROR_COLOR,f"[-] Perimssion denied: Unable to read {filepath}", Style.RESET_ALL)
    except OSError as e:
        print(ERROR_COLOR,f"[-] An OS error occurred while creating file: {e.strerror}", Style.RESET_ALL)
    except Exception as e:
        print(ERROR_COLOR,f"[-] An unexpected error occurred while creating file: {str(e)}", Style.RESET_ALL)
    return False


def terminate_program(message:Optional[str], exit_code:int = 1) -> None:
    """
    Prints an error message and terminates the program.

    :param message: The error message to display.
    :param exit_code: The exit code to return when terminating the program.
    """
    if message:
        print(ERROR_COLOR, message,Style.RESET_ALL)
    print(WARNING_COLOR, "[!] Exitting..", Style.RESET_ALL)
    sys.exit(exit_code)