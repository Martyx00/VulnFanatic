from binaryninja import *
import json
from ..trackers.function_tracer2 import FunctionTracer
from .query import Sources, _or_, _and_
from ..utils.utils import get_xrefs_of_symbol

class Scanner2(BackgroundTaskThread):
    def __init__(self,rules_path,bv):
        self.progress_banner = f"[VulnFanatic] Running the scanner ... "
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.bv = bv
        with open(rules_path,'r') as rules_file:
            self.rules = json.load(rules_file)
         
    def run(self):
        # For each rule in self.rules
        function_counter = 0
        finding_counter = 0
        for function in self.rules["functions"]:
            function_counter += 1
            function_refs = get_xrefs_of_symbol(self.bv,function)
            xref_counter = 1 
            # Recursively get all calls with the details
            for xref in function_refs:
                self.progress = f"{self.progress_banner} - Scanning xrefs to function '{function}' ({function_counter}/{len(self.rules['functions'])}):  xref ({xref_counter}/{len(function_refs)})"
                xref_counter += 1
                fun_trace = FunctionTracer(self.bv)
                trace = fun_trace.selected_function_tracer(xref,xref.function.source_function)
                # Check all variants
                for test_case in self.rules["test_cases"]:
                    if function in test_case["functions"]:
                        for variant in test_case["variants"]:
                            # Sources are not empty
                            if trace and trace["sources"]:
                                sources = Sources(trace["sources"])
                                query_result = eval(variant["where"])
                                if query_result.get_sources():
                                    details = self.create_description(query_result.get_sources())
                                    tag = xref.function.source_function.create_tag(self.bv.tag_types["[VulnFanatic] "+variant["confidence"]], f'{test_case["name"]}: {test_case["details"]}\n{details}', True)
                                    xref.function.source_function.add_user_address_tag(xref.address, tag)
                                    log_info(variant["confidence"] + " " +f'{test_case["name"]}')
                                    finding_counter += 1
                                    break
    
                

    def create_description(self,sources):
        desc = ""
        src_counter = 0
        '''for src in sources:
            src_counter +=1 
            if "constant" in src["var_type"]:
                continue
            desc += f"\nSource #{src_counter}:\n"
            if src["def_instruction_address"]:
                desc += f"  - Source of param[{src['param']}] at {hex(src['def_instruction_address'])}@{src['function_name']}\n"
            elif "param" in src["var_type"]:
                if f"{src['function'].parameter_vars[int(src['var_type'].split(':')[1])]} source of param[{src['param']}]" not in src["function"].comment:
                    desc += f"  - {src['function'].parameter_vars[int(src['var_type'].split(':')[1])]} of {src['function_name']} source of param[{src['param']}]\n"
            # Highlight/comment function calls
            for fun_call in src["function_calls"]:
                desc += f"  - Function call of {fun_call['function_name']} at {hex(fun_call['call_address'])} affecting param[{src['param']}]\n"
            # Highlight/comment ifs
            for if_dep in src["if_dependencies"]:
                # Highlight the if instruction
                desc += f"  - Source affected by IF instruction at {hex(if_dep['if_instruction_address'])} with condition '{str(if_dep['if_instruction'])}'\n"
                for origin in if_dep["var_origins"]:
                    for fun_call in origin["function_calls"]:
                        desc += f"    - IF instruction affected by call to function {fun_call['function_name']} at {hex(fun_call['call_address'])}\n"'''
        return desc