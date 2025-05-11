import vt


class VirusTotal:
    def __init__(self, settings):
        self.client = vt.Client(settings["virustotal_api_key"])


    def check_hash(self, hash: str):
        file = self.client.get_object("/files/{}", hash)
        last_analysis = file.last_analysis_stats
        
        return {"malicious_count": last_analysis["malicious"], "suspicious_count": last_analysis["suspicious"], "harmless_count": last_analysis["harmless"]}


    def check_url(self, url: str):
        url_id = vt.url_id("http://www.virustotal.com")
        url = self.client.get_object("/urls/{}", url_id)
        
        last_analysis = url.last_analysis_stats
        return {"times_submitted": url.times_submitted, "malicious_count": last_analysis["malicious"], "suspicious_count": last_analysis["suspicious"], "harmless_count": last_analysis["harmless"]}


    def check_domain():
        # ?
        pass


    def check_ip():
        # ?
        pass


    def scan_file():
        # is it free?
        pass