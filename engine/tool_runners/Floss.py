import subprocess
import json


class Floss:
    @staticmethod
    def run_floss(floss_path, target_path):
        # Run FLOSS with JSON output
        result = subprocess.run(
            [floss_path, "-j", target_path],
            capture_output=True, text=True, check=True
        )
            
        # Parse JSON output
        return json.loads(result.stdout)