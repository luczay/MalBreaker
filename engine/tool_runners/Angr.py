import angr
import monkeyhex
from networkx import drawing
from angrutils import *
import subprocess
from typing import Union


class Angr():
    def __init__(self, target_path, output_path):
        self.project = angr.Project(target_path, load_options={'auto_load_libs': False})
        self.output_path = output_path
        self.imports = {}
        
        imports_original = self.project.loader.main_object.imports
        for imp_name in imports_original:
            self.imports[self.project.loader.main_object.imports.get(imp_name).rebased_addr] = imp_name


    def get_cfg_fast(self, timeout):
        self.cfg_fast = self.project.analyses.CFGFast()
        self._cfg_to_svg("fast", timeout)

        # cfg_to_svg_with_timeout = SetTimeout(self._cfg_to_svg, timeout=5)
        # call the function
        # is_done, is_timeout, erro_message, results = cfg_to_svg_with_timeout(cfg_type = "fast")


    def get_cfg_emulated(self, timeout):
        self.cfg_emulated = self.project.analyses.CFGEmulated()
        self._cfg_to_svg("emulated", timeout)

    
    def get_function(self, cfg_type: str, function_address: Union[str, int]):
        cfg = None
        if cfg_type == "fast":
            cfg = self.cfg_fast
        elif cfg_type == "emulated":
            cfg = self.cfg_emulated

        if isinstance(function_address, str):
            return None
        
        function_obj = cfg.kb.functions.get(function_address)
        
        function_body = []
        if function_obj:
            strings = {}
            for string in function_obj.string_references():
                # address - value
                strings[string[0]] = string[1].decode('utf-8')

            fetched_instructions = self._fetch_all_instruction_from_function(function_obj)
            for i, insn in enumerate(fetched_instructions):
                if i + 1 < len(fetched_instructions):
                    instruction_dict = self._get_instruction_dict(insn, fetched_instructions[i + 1], strings)
                else:
                    instruction_dict = self._get_instruction_dict(insn, None, strings)
                
                function_body.append(instruction_dict)

        return function_body

    def _cfg_to_svg(self, cfg_type: str, timeout):
        if cfg_type == "fast":
            plot_cfg(self.cfg_fast, f"{self.output_path}\\cfg_temp", format="raw", asminst=True, remove_imports=True, remove_path_terminator=True)
        elif cfg_type == "emulated":
            plot_cfg(self.cfg_fast, f"{self.output_path}\\cfg_temp", format="raw", asminst=True, remove_imports=True, remove_path_terminator=True)  

        try:
            subprocess.run(
                f'dot -Tsvg "{self.output_path}\\cfg_temp.raw" > "{self.output_path}\\cfg_generated.svg"',
                shell=True ,
                timeout=timeout
            )
        except:
            print("[!] The CFG may be too complex to generate within the specified time, or the malware may employ anti-CFG generation techniques.\n " \
                        "Consider increasing the timeout threshold or investigating potential signs of anti-analysis methods.")


    def _fetch_all_instruction_from_function(self, function_obj):
        instructions = []
        for block in function_obj.blocks:
            for insn in block.capstone.insns:
                instructions.append(insn)

        return instructions
    

    def _get_instruction_dict(self, insn, next_insn, strings):
        op_string = None

        for i, op in enumerate(insn.operands):     
            if op.type == 2: # Immediate operand, like 0x...
                ptr_value = op.imm # immediate value
                imported_function_or_string = self._ptr_to_import_function_or_string(ptr_value, strings)

                if imported_function_or_string is not None:
                    op_string = insn.op_str.replace(hex(ptr_value), imported_function_or_string)
            elif op.type == 3:  # Memory operand
                # rip register's id: 41
                # displacement type: int - added or substracted from the base register
                operand_rank = i + 1
                base_register_id = op.mem.base
                displacement = op.mem.disp

                ptr_value = None

                if (operand_rank == 2 or operand_rank == 1) and base_register_id == 41:
                    if next_insn is not None:
                        ptr_value = next_insn.address + displacement

                if ptr_value is not None:
                    imported_function_or_string = self._ptr_to_import_function_or_string(ptr_value, strings)
                    
                    if imported_function_or_string is not None:
                        op_string = insn.op_str.split("[")[0] + f"[{imported_function_or_string}]"
        
        if op_string is None:
            op_string = insn.op_str
        
        instruction_dict = {"address": hex(insn.address), "mnemonic": insn.mnemonic, "operand": op_string}
        return instruction_dict
    

    def _ptr_to_import_function_or_string(self, ptr_value, strings):
        imported_function_or_string = None
        if ptr_value in self.imports:
            imported_function_or_string = f"import: {self.imports[ptr_value]}"
        elif ptr_value in strings:
            imported_function_or_string = f"string: {strings[ptr_value]}" 
        
        return imported_function_or_string
        