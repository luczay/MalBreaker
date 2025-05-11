import requests
import time
import json


class FileScan:
    def __init__(self, settings):
        self.api_key = settings["filescanio_api_key"]
        self.flow_id = ""


    def analyse(self, file_name: str, binary):
        self._upload(file_name, binary)
        
        result = self._retrieve_result()
        while not result["allFinished"]:
            result = self._retrieve_result()
            time.sleep(20)

        return result


    def _upload(self, file_name, binary):
        url = "https://www.filescan.io/api/scan/file"
        headers = {
            "X-Api-Key": self.api_key,  
            "accept": "application/json"
        }

        data = {
            "description": f"Uploaded {file_name}",
            "tags": "malware"
        }

        response = requests.post(url, headers=headers, files={"file": binary}, data=data)
        response_json = json.loads(response.text)

        self.flow_id = response_json["flow_id"]

    def _retrieve_result(self):
        url = f"https://www.filescan.io/api/scan/{self.flow_id}/report"

        headers = {
            "api-key": self.api_key,
        }

        response = requests.get(url, headers=headers)

        return json.loads(response.text)