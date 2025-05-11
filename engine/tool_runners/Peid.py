import peid


class Peid:
    @staticmethod
    def check_packing(target_path):
        result = peid.find_ep_only_signature(target_path)
        return result
    