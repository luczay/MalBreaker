import sys # killing the proccess
import os # checking existence and permissions of a file or directory
import json # for settings
import hashlib # getting the hash of a file
import re # regex for strings
from pathlib import Path # for reading settings 
from utility.CLI import CLI 

class FileUtility:
    @staticmethod
    def check_path_and_permission(path: str):
        if not os.path.exists(path):
            return False
        elif not os.access(path, os.W_OK):
            return False
        else:
            return True
        

    @staticmethod
    def get_sha256_hash(path: str):
        # calculate the hash of a file
        hash_object = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_object.update(chunk)
        return hash_object.hexdigest()
    
    
    @staticmethod
    def get_size(path: str):
        return os.path.getsize(path)
        

class OpSystemUtility:
    @staticmethod
    def quit():
        # exiting program with an error
        sys.exit(1) 


class SettingsUtility:
    def __init__(self):
        # load the settings file
        root_path = str(Path(__file__).resolve().parent.parent)
        settings_path = f"{root_path}\\settings.json"
        
        with open(settings_path, "r") as file:
            self.settings = json.load(file)


    def check_first_run(self):
        if self.settings["virustotal_api_key"] == "":
            # set colors
            CLI.print_in_red("[+] Please add your API kyes to the settings.json file before running the program!")
            return True
        

class StringUtility:
    @staticmethod
    def extract_strings(file_path: str, min_length: int = 4):
        # strings unix command implementation in python
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Extract ASCII and UTF-8 printable strings
        # \x20-\x7E covers standard printable ASCII characters (space to ~)
        strings = re.findall(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}", data)
        
        # Decode bytes to strings
        decoded_strings = [s.decode("utf-8", errors="ignore") for s in strings]
        
        return decoded_strings
    

class DotUtility:
    @staticmethod
    def CreateDOT(angr_output):
        pass