import requests
import json


class ThreatBook:
    def __init__(self, settings):
        self.api_key = settings["threatbook_api_key"]

    
    def check_ip(self, ip):
        url = "https://api.threatbook.io/v1/community/ip"

        params = {
                "apikey": self.api_key,
                "resource": ""
            }

        headers = {"accept": "application/json"}


        params["resource"] = ip
        response = requests.get(url, headers=headers, params=params)
        
        return json.loads(response.text)