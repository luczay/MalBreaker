import requests
import json


class AbuseIPDB:
    def __init__(self, settings):
        self.api_key = settings["abuseipdb_api_key"]


    def check_ip(self, ip):
        # Defining the api-endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': '',
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        querystring["ipAddress"] = ip
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)


        return json.loads(response.text)