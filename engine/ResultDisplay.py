import jinja2 
import os
from pathlib import Path


class ResultDisplay:
    def __init__(self, data_path, result_path):
        # pass mlabdata and malbresult
        self.data_path = data_path
        self.result_path = result_path

    def create_html_report(self, malbdata, malbresult):
        templateLoader = jinja2.FileSystemLoader( searchpath=f"{self.data_path}\\ResultTemplate" )

        templateEnv = jinja2.Environment( loader=templateLoader )

        TEMPLATE_FILE = "html_result_template.html"

        template = templateEnv.get_template( TEMPLATE_FILE )



        # Findings
        string_findings = self._collect_string_results(malbresult)
        
        virustotal_hash_result = self._get_virus_total_hash_result(malbresult)
        metadefender_hash_result = self._get_metadefender_hash_result(malbresult)

        packed_sections = malbresult["static"]["file"]["packed_sections"]
        if len(packed_sections) == 0:
            packed_sections.append({"name": "-", "entropy": "-", "offset": "-", "size": ""})

        sus_winapis =  malbresult["static"]["file"]["suspicious_winapis"]
        if len(sus_winapis) == 0:
            sus_winapis.append({"name": "-", "type": "-"})
        
        try:
            capa_rule_matches = malbresult["re"]["capa_function_and_matched_rules"]
            capa_functions = []
            for func in capa_rule_matches:
                capa_functions.append(func)
        except:
            # log error
            capa_rule_matches = [{"-": "-"}]
            capa_functions = ["-"]


        # Static
        file_info = malbdata["static"]["file_info"]

        version_details = malbdata["static"]["version_details"]
        if len(version_details) == 0:
            version_details.append({"name": "-", "detail": "-"})

        sections = malbdata["static"]["sections"]
        strings = self._collect_strings(malbdata, malbresult)
        
        pefile_imports = malbdata["static"]["pefile"]["imports"]
        if len(pefile_imports) == 0:
            pefile_imports.append({"import_entry": "-", "entry_imports": ["-"]})

        pefile_exports = malbdata["static"]["pefile"]["exports"]
        if len(pefile_exports) == 0:
            pefile_exports.append("-")

        pefile_resources = malbdata["static"]["pefile"]["resources"]
        if len(pefile_resources) == 0:
            pefile_resources.append("-")

        pefile_tls_callback = malbdata["static"]["pefile"]["tls_callback"]
        pefile_signature = malbdata["static"]["pefile"]["signature"]



        # Dynamic
        filescanio = self._get_filescanio_result(malbdata)
        hybridanalysis = self._get_hybridanalysis_result(malbdata)




        # Reverse Engineering
        # make it to the current lib location
        svg_location = f"{self.data_path}\\output.svg"

        capa_reversed_functions = malbresult["re"]["capa_reversed_functions"]
        if len(capa_reversed_functions) == 0:
            capa_reversed_functions = {"-": [{"address": "-", "mnemonic": "-", "operand": "-"}]}

        template_vars = {"string_findings": string_findings, "virustotal_hash_result": virustotal_hash_result,
                        "metadefender_hash_result": metadefender_hash_result, "packed_sections": packed_sections,
                        "sus_winapis": sus_winapis,
                        "file_info": file_info, "version_details": version_details, "sections": sections, 
                        "strings": strings, "pefile_imports": pefile_imports, "pefile_exports": pefile_exports, 
                        "pefile_resources": pefile_resources, "pefile_tls_callback": pefile_tls_callback, 
                        "pefile_signature": pefile_signature, "filescanio": filescanio, "hybridanalysis": hybridanalysis, "capa_functions": capa_functions, 
                        "capa_rule_matches": capa_rule_matches, "svg_location": svg_location, "capa_reversed_functions": capa_reversed_functions
                        }
        output_text = template.render( template_vars )

        with open(f"{self.result_path}\\rendered_template.html", "w+") as file:
            file.write(output_text)


    def _collect_string_results(self, malbresult):
        string_findings = []
        try:
            for string_type, string_details in malbresult["static"]["strings"].items():
                for string_item in string_details:
                    string = string_item["string"]
                    offset = string_item["offset"]
                    
                    virus_total_string = "-"
                    metadefender_string = "-"
                    threatbook_string = "-"
                    abuseipdb_string = "-"
                
                    for result in string_item["results"]:
                        if "virustotal" in result:
                            virus_total_string = ""
                            virus_total_string += f"Times Submitted: {result["virustotal"]["times_submitted"]} \n"
                            virus_total_string += f"Malicious Count: {result["virustotal"]["malicious_count"]} \n"
                            virus_total_string += f"Suspicious Count: {result["virustotal"]["suspicious_count"]} \n"
                            virus_total_string += f"Harmless Count: {result["virustotal"]["harmless_count"]}"
                        elif "metadefender" in result:
                            metadefender_string = ""
                            metadefender_string += f"Detected By: {result["metadefender"]["lookup_results"]["detected_by"]}"
                        elif "threatbook" in result:
                            threatbook_string = ""
                            threatbook_string += f"Whitelist: {result["threatbook"]["data"]["summary"]["whitelist"]} \n"
                            
                            judgment_str = ""
                            for judgment in result["threatbook"]["data"]["summary"]["judgments"]:
                                judgment_str += judgment + "|"

                            if judgment_string != "":
                                judgment_string = judgment_string[:-1]

                            threatbook_string += f"Whitelist: {result["threatbook"]["data"]["summary"]["whitelist"]}"
                            threatbook_string += f"Judgments: {judgment_str}"
                        elif "abuseipdb" in result:
                            abuseipdb_string = ""
                            abuseipdb_string += f"Whitelisted: {result["abuseipdb"]["data"]["isWhitelisted"]}\n"
                            abuseipdb_string += f"Abuse Score: {result["abuseipdb"]["data"]["abuseConfidenceScore"]}\n"
                            abuseipdb_string += f"Reports: {result["abuseipdb"]["data"]["totalReports"]}\n"
                    
                    string_findings.append({"string": string_item["string"], "virustotal": virus_total_string, "metadefender": metadefender_string, "threatbook": threatbook_string, "abuseipdb": abuseipdb_string, "offset": string_item["offset"]})
        except:
            string_findings = []
            string_findings.append({"string": "-", "virustotal": "-", "metadefender": "-", "threatbook": "-", "abuseipdb": "-", "offset": "-"})

        return string_findings


    def _get_virus_total_hash_result(self, malbresult):
        result = None

        try:
            result = {"malicious": malbresult["static"]["file"]["hash"]["results"][0]["virustotal"]["malicious_count"], 
            "suspicious": malbresult["static"]["file"]["hash"]["results"][0]["virustotal"]["suspicious_count"], 
            "harmless": malbresult["static"]["file"]["hash"]["results"][0]["virustotal"]["harmless_count"]}
        except:
            # log error
            result = {"malicious": "-", "suspicious": "-", "harmless": "-"}
        
        return result
    

    def _get_metadefender_hash_result(self, malbresult):
        metadefender_hash_result = None

        try:
            metadefender_hash_result = {"current": malbresult["static"]["file"]["hash"]["results"][1]["metadefender"]["last_av_scan"]["current_av_result_a"], 
                                        "all": malbresult["static"]["file"]["hash"]["results"][1]["metadefender"]["last_av_scan"]["scan_all_result_i"]}
        except:
            # log error
            metadefender_hash_result = {"current": "-", "all": "-"}

        return metadefender_hash_result
    

    def _collect_strings(self, malbdata, malbresult):
        strings = []

        try:
            for string_type, string_list in malbdata["static"]["strings"].items():
                # skipping runtime, because it contains information not strings

                if string_type == "runtime":
                    continue

                if (len(string_list) == 0):
                    continue
                
                for string in string_list:
                    category_result = "Uncategorised"
                    maliciousness = "-"
                    for category, categorised_strings in malbresult["static"]["strings"].items():
                        for category_string in categorised_strings:
                            if category_string["string"] == string["string"]:
                                maliciousness = self._get_category_info(category_string, category)
                                category_result = category
                                break

                    strings.append({"string": string["string"], "type": string_type, "category": category_result, "risk_level": maliciousness, "encoding": string["encoding"], "offset": string["offset"]})
        except:
            # log error
            strings.append({"string": "-", "type": "-", "category": "-", "risk_level": "-", "encoding": "-", "offset": "-"})
        
        return strings


    def _get_category_info(self, category_string, category):
        result_string = ""
        if category == "suspicious":
            result_string == "Suspicious"
        else:
            for result in category_string["results"]:
                try:
                    if "virustotal" in result:
                        result_string += f"Virustotal - Malicious: {result["virustotal"]["malicious_count"]}, Suspicious: {result["virustotal"]["suspicious_count"]}, Harmless: {result["virustotal"]["harmless_count"]}\n"
                    elif "metadefender" in result:
                        result_string += f"MetaDefender - Detected by: {result["metadefender"]["lookup_results"]["detected_by"]}\n"
                    elif "threat_book" in result:
                        judgment_string = ""
                        for judgment in result["threat_book"]["data"]["summary"]["judgments"]:
                            judgment_string += f"{judgment}|"
                        
                        if judgment_string != "":
                            judgment_string = judgment_string[:-1]

                        result_string += f"ThreatBook - Whitelist: {result["threat_book"]["data"]["summary"]["whitelist"]}, Judgment: {judgment_string}\n"
                    elif "abuseipdb" in result:
                        result_string += f"AbuseIPDB - Whitelist: {result["abuseipdb"]["data"]["isWhitelisted"]}, Abuse Confidence: {result["abuseipdb"]["data"]["abuseConfidenceScore"]}, Reports: {result["abuseipdb"]["data"]["totalReports"]}\n"
                except:
                    result_string = "Failed to retrieve information about the string using online static analysis tools."
        return result_string    
    

    def _get_filescanio_result(self, malbdata):
        filescanio = None
        try:
            for report_name, report in malbdata["dynamic"]["scan_results"]["filescanio"]["reports"].items():
                filescanio = {"verdict": report["finalVerdict"]["verdict"].lower(), "threat_level": report["finalVerdict"]["threatLevel"], "confidence": report["finalVerdict"]["confidence"]}

                break # first report only
        except:
            # log error
            filescanio = {"verdict": "-", "threat_level": "-", "confidence": "-"}

        return filescanio
    

    def _get_hybridanalysis_result(self, malbdata):
        hybridanalysis = []
        try:
            for scanner_name, scanner_result in malbdata["dynamic"]["scan_results"]["hybridanalysis"]["scanners_v2"].items():
                if scanner_result is not None:
                    hybridanalysis.append(scanner_result)
        except:
            # log error
            hybridanalysis = []
            hybridanalysis.append({"name": "-", "status": "-"})

        return hybridanalysis