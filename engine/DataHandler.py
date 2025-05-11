from datetime import datetime
from enum import Enum
import json
import os
from pathlib import Path


class DataTypes(Enum):
    HASH = 1
    FILE_INFO = 2
    FILE_VERSION = 3
    FLOSS = 4
    SECTIONS = 5
    DIE = 6
    PEFILE = 7
    FILESCANIO = 8
    HYBRIDANALYSIS = 9
    ANGR = 10
    CAPA = 11


class DataHandler:
    def __init__(self, data_path, result_path):
        self.data_path = data_path
        self.result_path = result_path

        with open(f"{self.data_path}\\MalBDataTemplate.json", "r") as file:
            self.malbdata = json.load(file)

        self.save()


    def save(self):
        with open(f"{self.result_path}\\MalbData.json", "w+") as file:
            json.dump(self.malbdata, file, indent=4)

    
    def load_data(self, type: DataTypes, data: object):
        if (type == DataTypes.HASH):
            self._hash_loader(data)
        elif (type == DataTypes.FILE_INFO):
            self._file_info_loader(data)
        elif (type == DataTypes.FILE_VERSION):
            self._file_version_loader(data)
        elif (type == DataTypes.FLOSS):
            self._floss_loader(data)
        elif (type == DataTypes.SECTIONS):
            self._sections_loader(data)
        elif (type == DataTypes.DIE):
            self._die_loader(data)
        elif (type == DataTypes.PEFILE):
            self._pefile_loader(data)
        elif (type == DataTypes.FILESCANIO):
            self._filescanio_loader(data)
        elif (type == DataTypes.HYBRIDANALYSIS):
            self._hybridanalysis_loader(data)
        elif (type == DataTypes.ANGR):
            self._angr_loader(data)
        elif (type == DataTypes.CAPA):
            self._capa_loader(data)

    
    def _hash_loader(self, hash: str):
        self.malbdata["static"]["file_info"]["hash"] = hash


    def _file_info_loader(self, file_info):
        data_info = file_info["data"]["Info"]

        self.malbdata["static"]["file_info"]["architecture"] = data_info["Architecture"]
        self.malbdata["static"]["file_info"]["endianness"] = data_info["Endianness"]
        self.malbdata["static"]["file_info"]["extensio"] = data_info["Extension"]
        self.malbdata["static"]["file_info"]["name"] = Path(data_info["File name"]).name
        self.malbdata["static"]["file_info"]["file_type"] = data_info["File type"]
        self.malbdata["static"]["file_info"]["mode"] = data_info["Mode"]
        self.malbdata["static"]["file_info"]["size"] = data_info["Size"]
        self.malbdata["static"]["file_info"]["string"] = data_info["String"]
        self.malbdata["static"]["file_info"]["type"] = data_info["Type"]

    def _file_version_loader(self, file_version):
        self.malbdata["static"]["version_details"] = file_version


    def _floss_loader(self, floss_data):
        self.malbdata["static"]["strings"]["runtime"] = floss_data["metadata"]["runtime"]

        strings_data = floss_data["strings"]
        self.malbdata["static"]["strings"]["decoded_strings"] = strings_data["decoded_strings"]
        self.malbdata["static"]["strings"]["language_strings"] = strings_data["language_strings"]
        self.malbdata["static"]["strings"]["language_strings_missed"] = strings_data["language_strings_missed"]
        self.malbdata["static"]["strings"]["stack_strings"] = strings_data["stack_strings"]
        self.malbdata["static"]["strings"]["static_strings"] = strings_data["static_strings"]
        self.malbdata["static"]["strings"]["tight_strings"] = strings_data["tight_strings"]


    def _sections_loader(self, sections):
        self.malbdata["static"]["sections"] = sections["records"]


    def _die_loader(self, die_data):
        self.malbdata["static"]["die"] = die_data["detects"]

    
    def _pefile_loader(self, pefile_data):
        self.malbdata["static"]["pefile"] = pefile_data

    def _filescanio_loader(self, filescanio_data):
        self.malbdata["dynamic"]["scan_results"]["filescanio"] = filescanio_data


    def _hybridanalysis_loader(self, hybridanalysis_data):
        self.malbdata["dynamic"]["scan_results"]["hybridanalysis"] = hybridanalysis_data


    def _angr_loader(self, angr_data):
        pass


    def _capa_loader(self, capa_data):
        self.malbdata["re"]["capa"] = capa_data