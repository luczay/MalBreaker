import subprocess
import json


class Capa:
    @staticmethod
    def run_capa(capa_path, target_path):
        # Run Capa with JSON output
        result = subprocess.run(
            [capa_path, "-j", target_path],
            capture_output=True, text=True, check=True
        )

        return json.loads(result.stdout)