from pathlib import Path
import re
import json


class ResultHandler:
    def __init__(self, data_path, result_path):
        self.data_path = data_path
        self.result_path = result_path

        with open(f"{self.data_path}\\MalBResultTemplate.json", "r") as file:
            self.malbresult = json.load(file)

        self.save()


    def process_static_data(self, malbdata):
        self.malbresult["static"]["file"]["hash"]["value"] = malbdata["static"]["file_info"]["hash"]

        self._find_urls(malbdata)
        self._find_domains(malbdata)
        self._find_ips(malbdata)
        self._find_url_paths(malbdata)
        self._handle_sections(malbdata)

    
    def save(self):
        with open(f"{self.result_path}\\MalbResult.json", "w+") as file:
            json.dump(self.malbresult, file, indent=4)


    def process_dynamic_data(self, malbdata):
        # by using a specific logic add results from the tools to malbresult
        # if malicious
        # move the relevant details to malbresult

        for report_name, report in malbdata["dynamic"]["scan_results"]["filescanio"]["reports"].items():
            if report["finalVerdict"]["verdict"].lower() == "malicious" or report["finalVerdict"]["verdict"].lower() == "suspicious":
                self.malbresult["dynamic"]["filescanio"] = report

            break # first report only

        for scanner_name, scanner_result in malbdata["dynamic"]["scan_results"]["hybridanalysis"]["scanners_v2"].items():
            if scanner_result is not None and (scanner_result["status"] == "malicious" or scanner_result["status"] == "suspicious"):
                self.malbresult["dynamic"]["hybridanalysis"].append(scanner_result)


    def process_re_data(self, malbdata):
        function_and_matched_rules = {}

        for rule in malbdata["re"]["capa"]["rules"]:
            if malbdata["re"]["capa"]["rules"][rule]["matches"][0][0]["type"] == "absolute":
                function_offset = malbdata["re"]["capa"]["rules"][rule]["matches"][0][0]["value"]
            else:
                function_offset = malbdata["re"]["capa"]["rules"][rule]["matches"][0][0]["type"]

            if function_offset in function_and_matched_rules:
                function_and_matched_rules[function_offset].append(rule)
            else:
                function_and_matched_rules[function_offset] = [rule]

        self.malbresult["re"]["capa_function_and_matched_rules"] = function_and_matched_rules


    def _find_urls(self, malbdata):
    # ADD A MALICIOUS FLAG AND SET 0 BY DEFAULT THEN SET LATER
    #     "strings": {
    #     "runtime": {},
    #     "decoded_strings": [],
    #     "language_strings": [],
    #     "language_strings_missed": [],
    #     "stack_strings": [],
    #     "static_strings": [],
    #     "tight_strings": []
    # },
        url_regex = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
        self._regex_and_collect(url_regex, "urls", malbdata)

    
    def _find_domains(self, malbdata):
        domain_regex = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
        self._regex_and_collect(domain_regex, "domains", malbdata)


    def _find_ips(self, malbdata):
        ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        self._regex_and_collect(ip_regex, "ips", malbdata)

    
    def _find_url_paths(self, malbdata):
        path_regex = re.compile(r"/[^?\s#]*")
        self._regex_and_collect(path_regex, "url_paths", malbdata)
        
    

    def _handle_sections(self, malbdata):
        for section in malbdata["static"]["sections"]:
            if section["status"] == "packed":
                self.malbresult["static"]["file"]["packed_sections"].append(section)


    def _regex_and_collect(self, regex, regex_type: str, malbdata):
        for string_type, string_list in malbdata["static"]["strings"].items():
            # skipping runtime, because it contains information not strings

            if string_type == "runtime":
                continue

            if (len(string_list) == 0):
                continue

            for string in string_list:
                if (regex.match(string["string"])):
                    if regex_type == "domains" and string["string"].split(".")[-1] == "dll":
                        # skip dlls
                        continue

                    self.malbresult["static"]["strings"][regex_type].append({"encoding": string["encoding"], 
                                                                         "offset": string["offset"], 
                                                                         "string": string["string"],
                                                                         "results": []})