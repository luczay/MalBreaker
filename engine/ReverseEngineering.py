from engine.tool_runners.Angr import Angr


class ReverseEngineering:
    def __init__(self, angr: Angr, malbdata, malbresult):
        self.angr = angr
        self.malbdata = malbdata
        self.malbresult = malbresult


    def get_functions_for_capa(self):
        for function_address, rule_list in self.malbresult["re"]["capa_function_and_matched_rules"].items():
            function_body = self.angr.get_function("fast", function_address)

            if function_body is not None:
                self.malbresult["re"]["capa_reversed_functions"][str(function_address)] = function_body