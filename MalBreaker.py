from engine.DataHandler import DataHandler # internal - malbdata handler
from engine.ResultHandler import ResultHandler # internal - malbresult handler
from engine.DataHandler import DataTypes # internal - data types for DataHandler
from engine.ResultDisplay import ResultDisplay
from engine.tool_runners.PEFile import PEFile # internal - pefile package wrapper
from engine.tool_runners.Floss import Floss # internal - floss runner 
from engine.tool_runners.DIE import DIE # internal - DIE runner
from engine.tool_runners.FIleScan_io import FileScan
from engine.tool_runners.HybridAnalysis import HybridAnalysis
from engine.tool_runners.Angr import Angr
from engine.tool_runners.Capa import Capa
from engine.StaticAnalysis import StaticAnalysis
from engine.ReverseEngineering import ReverseEngineering
from utility.Utilities import FileUtility # internal file utility
from utility.Utilities import OpSystemUtility # internal op system utlity
from utility.Utilities import SettingsUtility # internal settings utility
from utility.CLI import CLI # internal CLI helper
from pathlib import Path
import argparse # getting CLI flags
from datetime import datetime
import os
import concurrent.futures
import threading


class MalBreaker:
    def __init__(self):
        self.data_path = f"{str(Path(__file__).resolve().parent)}\\data"

        self.settings_util = SettingsUtility()
        if self.settings_util.check_first_run():
            OpSystemUtility.quit()

        self.settings = self.settings_util.settings

        # CLI flags
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", required=True, help="Path of the target file")
        parser.add_argument("-s", "--suspicious-strings", required=False, help="Path to a custom list of suspicious strings")
        parser.add_argument("-i", "--ignore-errors", required=False, action='store_true', help="Ignore non-critical errors and continue execution")
        parser.add_argument("-c", "--cfg-timeout", required=False, help="CFG generation timeout in seconds (default: 60s).")
        # parser.add_argument("-v", "--verbose", required=False, help="Display more info/log")

        # use bool flags to turn on and off features like dynamic analysis
        # parser.add_argument('-r', action='store_true', help='Enable recursive mode.')
        
        args = parser.parse_args()

        # Set path variables
        self.target_path = args.target

        # Check if the target and output paths exist
        if not FileUtility.check_path_and_permission(self.target_path):
            CLI.print_in_red("The program does not have permission to access the target path, or the target path does not exist")
            OpSystemUtility.quit()

        if args.suspicious_strings is not None:
            self.settings["suspicious_strings_path"] = args.suspicious_strings
        else:
            self.settings["suspicious_strings_path"] = f"{self.data_path}\\Keywords\\only_keywords.txt"
        
        if args.ignore_errors:
            self.ignore_errors = True
        else:
            self.ignore_errors = False

        if args.cfg_timeout is not None:
            self.cfg_timeout = args.cfg_timeout
        else:
            self.cfg_timeout = 60

        self.file_name = Path(self.target_path).name

        # initialise DataHandler
        now = datetime.now()
        formatted_datetime = now.strftime("%Y-%m-%d_%H_%M_%S")
        
        self.output_path = f"{self.data_path}\\{formatted_datetime}"
        os.makedirs(self.output_path)
    
        self.dh = DataHandler(self.data_path, self.output_path)

        # initilise ResultHandler
        self.rh = ResultHandler(self.data_path, self.output_path)

        # initialise PEFile
        self.pefile_tool = PEFile(self.target_path)

        with open(self.target_path, 'rb') as file:
            self.binary = file.read()

        self.angr = Angr(self.target_path, self.output_path)

        self.rd = ResultDisplay(self.data_path, self.output_path)

    def main(self):
        # CLI.print_settings(self.settings)

        try:
            print("[*] Calculating the file hash...")
            self.hash = self.get_hash()
            CLI.print_in_green("[+] File hash calculation finished successfully")
        except Exception as e:
            CLI.print_in_red("[!] Error during file hash calculation")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")

            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[+] Reading file information...")
            self.get_file_info()
            CLI.print_in_green("[+] Successfully retrieved file information")
        except Exception as e:
            CLI.print_in_red("[!] Failed to read file information")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")

            if not self.ignore_errors:
                OpSystemUtility.quit()
        
        try:
            print("[*] Reading file version...")
            self.get_file_version()
            CLI.print_in_green("[+] Successfully retrieved file version")
        except Exception as e:
            CLI.print_in_red("[!] Failed to read file version")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()
        
        try:
            print("[*] Extracting strings with FLOSS...")
            self.get_strings_with_floss()
            CLI.print_in_green("[+] Successfully extracted strings with FLOSS")
        except Exception as e:
            CLI.print_in_red("[!] Failed to extract strings with FLOSS")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            OpSystemUtility.quit()

        try:
            print("[*] Extracting section info with DIE...")
            self.get_section_info_with_DIE()
            CLI.print_in_green("[+] Successfully extracted section info with DIE")
        except Exception as e:
            CLI.print_in_red("[!] Failed to extract section info with DIE")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Extracting static data with DIE...")
            self.get_details_with_DIE()
            CLI.print_in_green("[+] Successfully extracted data with DIE")
        except Exception as e:
            CLI.print_in_red("[!] Failed to extract data with DIE")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Extracting static data with pefile...")
            self.get_static_details_with_pefile()
            CLI.print_in_green("[+] Successfully extracted static data")
        except Exception as e:
            CLI.print_in_red("[!] Failed to extract static data")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Processing static data...")
            self.process_static_data()
            CLI.print_in_green("[+] Successfully processed static data")
        except Exception as e:
            CLI.print_in_red("[!] Failed to process static data")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Performing static analysis")
            # add domains, ips, urls, etc to malbdata and/or malbresult for testing!!!!!!!!!!
            # self.dh.malbdata["static"]["strings"]["static_strings"].append({"encoding": "test", 
            #                                                              "offset": "test", 
            #                                                              "string": "babydoge.lol"})

            # self.dh.malbdata["static"]["strings"]["static_strings"].append({"encoding": "test", 
            #                                                              "offset": "test", 
            #                                                              "string": "92.255.85.253"})
            
            # self.dh.malbdata["static"]["strings"]["static_strings"].append({"encoding": "test", 
            #                                                              "offset": "test", 
            #                                                              "string": "https://www.timeout.com/budapest/restaurants/best-restaurants-in-budapest"})
            
            # self.dh.save()


            # self.rh.malbresult["static"]["strings"]["domains"].append({"encoding": "test", 
            #                                                              "offset": "test", 
            #                                                              "string": "babydoge.lol",
            #                                                              "results": []})
            
            # self.rh.malbresult["static"]["strings"]["ips"].append({"encoding": "test", 
            #                                                              "offset": "test", 
            #                                                              "string": "92.255.85.253",
            #                                                              "results": []})

            # self.rh.malbresult["static"]["strings"]["urls"].append({"encoding": "test", 
            #                                                              "offset": "test", 
            #                                                              "string": "https://www.timeout.com/budapest/restaurants/best-restaurants-in-budapest",
            #                                                              "results": []})

            # self.rh.save()

            self.perform_static_analysis()
            CLI.print_in_green("[+] Static analysis completed successfully")
        except Exception as e:
            CLI.print_in_red("[!] Static analysis failed")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("Running dynamic analysis using Hybrid Analysis and Filescan.io...")
            self.run_dynamic_analysis()
            CLI.print_in_green("[+] Dynamic analysis completed successfully")
        except Exception as e:
            CLI.print_in_red("[!] Dynamic analysis failed")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Processing dynamic data...")
            self._process_dynamic_data()
            CLI.print_in_green("[+] Successfully processed dynamic data")
        except Exception as e:
            CLI.print_in_red("[!] Failed to process dynamic data")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Generating Control Flow Graph (CFG)...")
            self.get_cfg_with_angr()
            CLI.print_in_green("[+] CFG generation complete")
        except Exception as e:
            CLI.print_in_red("[!] Failed to generate CFG")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Reverse engineering with Capa...")
            self.get_re_details_with_capa()
            CLI.print_in_green("[+] Reverse engineering complete")
        except Exception as e:
            CLI.print_in_red("[!] Failed to reverse engineer")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()
        
        try:
            print("[*] Processing reverse engineering data...")
            self.process_re_data()
            CLI.print_in_green("[+] Successfully processed reverse engineering data")
        except Exception as e:
            CLI.print_in_red("[!] Failed to process reverse engineering data")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()

        try:
            print("[*] Performing reverse engineering...")
            self.perform_reverse_engineering()
            CLI.print_in_green("[+] Reverse engineering completed successfully")
        except Exception as e:
            CLI.print_in_red("[!] Reverse engineering failed")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            
            if not self.ignore_errors:
                OpSystemUtility.quit()
        
        try:
            print("[*] Rendering HTML report...")
            self.render_html_report()
            CLI.print_in_green("[+] Successfully rendered HTML result")
        except Exception as e:
            CLI.print_in_red("[!] Rendering failed")
            CLI.print_in_red(f"[!] {type(e).__name__} - {e}")
            

    def get_hash(self):
        hash = FileUtility.get_sha256_hash(self.target_path)
        self.dh.load_data(DataTypes.HASH, hash)
        self.dh.save()


    def get_file_info(self):
        file_info = DIE.read_file_info(self.target_path)
        self.dh.load_data(DataTypes.FILE_INFO, file_info)
        self.dh.save()
    

    def get_file_version(self):
        file_info = self.pefile_tool.get_pe_version_info()
        self.dh.load_data(DataTypes.FILE_VERSION, file_info)
        self.dh.save()

    
    def get_strings_with_floss(self):
        extracted_strings = Floss.run_floss(self.settings["floss_path"], self.target_path)
        self.dh.load_data(DataTypes.FLOSS, extracted_strings)
        self.dh.save()

    
    def get_section_info_with_DIE(self):
        sections = DIE.read_sections(self.target_path)
        self.dh.load_data(DataTypes.SECTIONS, sections)
        self.dh.save()

    
    def get_details_with_DIE(self):
        details = DIE.run(self.target_path)
        self.dh.load_data(DataTypes.DIE, details)
        self.dh.save()


    def get_static_details_with_pefile(self):
        static_details = self.pefile_tool.extract_details()
        self.pefile_tool.close()
        self.dh.load_data(DataTypes.PEFILE, static_details)
        self.dh.save()

    
    def process_static_data(self):
        self.rh.process_static_data(self.dh.malbdata)
        self.rh.save()

    
    def perform_static_analysis(self):
        static_analysis = StaticAnalysis(self.settings, self.target_path, self.dh.malbdata, self.rh.malbresult)
        static_analysis.analyse()

        # use datahandler load pattern!
        self.rh.malbresult = static_analysis.malbresult
        self.rh.save()


    def run_dynamic_analysis(self):
        hybridanalysis = HybridAnalysis(self.settings)
        hybridanalysis_result = hybridanalysis.analyse(self.file_name, self.binary)

        filescanio = FileScan(self.settings)
        filescanio_result = filescanio.analyse(self.file_name, self.binary)

        self.dh.load_data(DataTypes.FILESCANIO, filescanio_result)
        self.dh.load_data(DataTypes.HYBRIDANALYSIS, hybridanalysis_result)
        self.dh.save()
        
        # with concurrent.futures.ThreadPoolExecutor() as executor:
        #     # Schedule the functions to run concurrently
        #     futures = {
        #         executor.submit(self._get_dynamic_details_with_filescan_io): "Hybrid Analysis",
        #         executor.submit(self._get_dynamic_details_with_hybrid_analysis): "Filescan.io"
        #     }
            
        #     for future in concurrent.futures.as_completed(futures):
        #         future.result() # Retrieve the result to check for exceptions


    # def _get_dynamic_details_with_filescan_io(self):
    #     lock = threading.Lock()

    #     filescanio = FileScan(self.settings)
    #     dynamic_details = filescanio.analyse(self.file_name, self.binary)
    #     print(f"filescan result: {dynamic_details}")

    #     with lock:
    #         self.dh.load_data(DataTypes.FILESCANIO, dynamic_details)
    #         self.dh.save()


    # def _get_dynamic_details_with_hybrid_analysis(self):
    #     lock = threading.Lock()
    
    #     hybridanalysis = HybridAnalysis(self.settings)
    #     dynamic_details = hybridanalysis.analyse(self.file_name, self.binary)
    #     print(f"hybrid analysis result: {dynamic_details}")

    #     with lock:
    #         self.dh.load_data(DataTypes.HYBRIDANALYSIS, dynamic_details)
    #         self.dh.save()


    def _process_dynamic_data(self):
        self.rh.process_dynamic_data(self.dh.malbdata)
        self.rh.save()


    def get_cfg_with_angr(self):
        self.angr.get_cfg_fast(self.cfg_timeout)


    def get_re_details_with_capa(self):
        capa_result = Capa.run_capa(self.settings["capa_path"], self.target_path)
        self.dh.load_data(DataTypes.CAPA, capa_result)
        self.dh.save()
    
    
    def process_re_data(self):
        self.rh.process_re_data(self.dh.malbdata)
        self.rh.save()


    def perform_reverse_engineering(self):
        re = ReverseEngineering(self.angr, self.dh.malbdata, self.rh.malbresult)
        re.get_functions_for_capa()

        self.rh.malbresult = re.malbresult
        self.rh.save()


    def render_html_report(self):
        self.rd.create_html_report(self.dh.malbdata, self.rh.malbresult)


if __name__ == "__main__":
    print("\n\n")
    program = MalBreaker()
    program.main()