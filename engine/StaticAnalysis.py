from engine.tool_runners.MetaDefender import MetaDefender
from engine.tool_runners.ThreatBook import ThreatBook
from engine.tool_runners.VirusTotal import VirusTotal
from engine.tool_runners.AbuseIPDB import AbuseIPDB
from pathlib import Path
import time


class StaticAnalysis:
    def __init__(self, settings, target_path, malbdata, malbresult):
        self.settings = settings
        self.target_path = target_path
        self.malbdata = malbdata
        self.malbresult = malbresult
        self.virus_total = VirusTotal(settings)
        self.threat_book = ThreatBook(settings)
        self.metadefender = MetaDefender(settings)
        self.abusedipdb = AbuseIPDB(settings)

        win_api_data_path = f"{str(Path(__file__).resolve().parent.parent)}\\data\\WinAPI"
        with open(f"{win_api_data_path}\\injection.txt", "r") as file:
            self.injection_winapis = set(file.readlines())

        with open(f"{win_api_data_path}\\keylogging.txt", "r") as file:
            self.keylogging_winapis = set(file.readlines())

        with open(f"{win_api_data_path}\\process_hooking.txt", "r") as file:
            self.process_hooking_winapis = set(file.readlines())

        with open(f"{win_api_data_path}\\unpacking.txt", "r") as file:
            self.unpacking_winapis = set(file.readlines())


    def analyse(self):
        self._find_interesting_strings()
        self._get_urls_details()
        self._get_ips_info()
        self._get_domains_info()
        self._get_hash_info()
        self._find_suspcious_win_api_calls()

        self.virus_total.client.close()


    def _find_interesting_strings(self):
        # load strings
        # set is O(1)
        with open(self.settings["suspicious_strings_path"], "r") as f:
            threat_keywords = set(line.strip().lower().replace("*", "") for line in f)

        for string_type, string_list in self.malbdata["static"]["strings"].items():
            if string_type == "runtime":
                continue

            for item in string_list:
                if item.get("string") in threat_keywords:
                    self.malbresult["static"]["strings"]["suspicious"].append(item)
    

    def _get_urls_details(self):
        for url in self.malbresult["static"]["strings"]["urls"]:
            # could cause update issues
            url["results"].append({"virustotal": self.virus_total.check_url(url["string"])})
            url["results"].append({"metadefender": self.metadefender.check_url(url["string"])})

            # api rate limit
            time.sleep(18)             


    def _get_ips_info(self):
        for ip in self.malbresult["static"]["strings"]["ips"]:
            # could cause update issues
            ip["results"].append({"threat_book": self.threat_book.check_ip(ip["string"])})
            ip["results"].append({"metadefender": self.metadefender.check_ip(ip["string"])})
            ip["results"].append({"abuseipdb": self.abusedipdb.check_ip(ip["string"])})

            # api rate limit
            time.sleep(18) 


    def _get_domains_info(self):
        # error handlig? 
        # fails silently?
        # one more tool for domain info
        for domain in self.malbresult["static"]["strings"]["domains"]:
            # could cause update issues
            domain["results"].append({"metadefender": self.metadefender.check_domain(domain["string"])})

            # api rate limit
            time.sleep(18) 


    def _get_hash_info(self):
        self.malbresult["static"]["file"]["hash"]["results"].append({
                "virustotal": self.virus_total.check_hash(self.malbresult["static"]["file"]["hash"]["value"])
            })
        
        self.malbresult["static"]["file"]["hash"]["results"].append({
                "metadefender": self.metadefender.check_hash(self.malbresult["static"]["file"]["hash"]["value"])
            })
        

    def _find_suspcious_win_api_calls(self):
        # imported functions
        # compare to list
        for d in self.malbdata["static"]["pefile"]["imports"]:
            for key, value in d.items():
                if key == "import_entry":
                    self._check_win_api(value)
                else:
                    for imported_function in value:
                        self._check_win_api(imported_function)

    
    def _check_win_api(self, function):
        if function in self.injection_winapis:
            self.malbresult["static"]["file"]["suspicious_winapis"].append({"name": function, "type": "injection"})

        if function in self.keylogging_winapis:
            self.malbresult["static"]["file"]["suspicious_winapis"].append({"name": function, "type": "keylogging"})

        if function in self.process_hooking_winapis:
            self.malbresult["static"]["file"]["suspicious_winapis"].append({"name": function, "type": "process_hooking"})

        if function in self.unpacking_winapis:
            self.malbresult["static"]["file"]["suspicious_winapis"].append({"name": function, "type": "unpacking"})