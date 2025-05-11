import subprocess
import json


class DIE:
    @staticmethod
    def read_file_info(target_path):
        # Run DIE to read file info with JSON output
        result = subprocess.run(
            ["diec", "-i", "-j", target_path],
            capture_output=True, text=True, check=True
        )
            
        # Parse JSON output
        return json.loads(result.stdout)
    

    @staticmethod
    def read_sections(target_path):
        # Run DIE to read file sections with JSON output
        result = subprocess.run(
            ["diec", "-e", "-j", target_path],
            capture_output=True, text=True, check=True
        )
            
        # Parse JSON output
        return json.loads(result.stdout)
    

    @staticmethod
    def run(target_path):
        # Run DIE
        result = subprocess.run(
            ["diec", "-j", target_path],
            capture_output=True, text=True, check=True
        )
        
        # remove the first line: "[!] Heuristic scan is disabled. Use '--heuristicscan' to enable"
        result_str = ""
        for line in result.stdout.split("\n"):
            if (line.startswith("[!]")):
                continue
            else:
                result_str += line

        return json.loads(result_str)