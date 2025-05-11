import requests
import json
from urllib.parse import quote


class MetaDefender():
    def __init__(self, settings):
        self.api_key = settings["metadefender_api_key"]

    
    def check_hash(self, hash):
        url = f"https://api.metadefender.com/v5/threat-intel/file-analysis/{hash}"
        headers = {
        "apikey": self.api_key
        }

        response = requests.request("GET", url, headers=headers)

        return json.loads(response.text)


    def check_ip(self, ip):
        url_base = "https://api.metadefender.com/v4/ip/"
        headers = {
        "apikey": self.api_key
        }

        url = f"{url_base}/{ip}"
        response = requests.request("GET", url, headers=headers)

        return json.loads(response.text)


    def check_url(self, target_url):
        url_base = "https://api.metadefender.com/v4/url"
        headers = {
        "apikey": self.api_key
        }

        encoded_target_url = quote(target_url, safe='')
        url = f"{url_base}/{encoded_target_url}"
        response = requests.request("GET", url, headers=headers)

        return json.loads(response.text)


    def check_domain(self, domain):
        url_base = "https://api.metadefender.com/v4/domain"
        headers = {
        "apikey": self.api_key
        }

        url = f"{url_base}/{domain}"
        response = requests.request("GET", url, headers=headers)

        return json.loads(response.text)
