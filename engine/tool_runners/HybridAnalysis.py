import requests
import time
import json 


class HybridAnalysis:
    def __init__(self, settings):
        self.api_key = settings["hybridanalysis_api_key"]
        self.scan_id = ""

    def analyse(self, file_name, binary):
        self._upload(file_name, binary)

        done = False
        while not done:
            done = True
            result = self._retrive_result()

            for scanner in result["scanners"]:
                if scanner["progress"] != 100:
                    done = False

            for scanner, scanner_values in result["scanners_v2"].items():
                if scanner_values is not None and scanner_values["progress"] != 100:
                    done = False
            
            if not done:
                time.sleep(20)


        while not result["finished"]:
            result = self._retrive_result()
            time.sleep(20)

        return result
        
    
    def _upload(self, file_name, binary):
        url = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"

        headers = {
            "api-key": self.api_key 
        }

        params = {
            "scan_type": "all", 
            "comment": "Testing quick scan #malware",
            "submit_name": file_name
        }

        response = requests.post(url, headers=headers, files={"file": binary}, data=params)
        response_json = json.loads(response.text)
        
        # retrieve scan id from result
        self.scan_id = response_json["id"]

        # add logic to handle existing reports
        if len(response_json["reports"]) > 0:
            self.reports = response_json["reports"]

    
    def _retrive_result(self):
        url = f"https://www.hybrid-analysis.com/api/v2/quick-scan/{self.scan_id}"

        headers = {
            "api-key": self.api_key,
        }

        response = requests.get(url, headers=headers)
        response_json = json.loads(response.text)

        return response_json