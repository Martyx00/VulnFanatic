from binaryninja import *
import json
from .free_scanner2 import FreeScanner2
from ..trackers.function_tracer2 import FunctionTracer
from .query import Sources, _or_, _and_
from ..utils.utils import get_xrefs_of_symbol

class Scanner2(BackgroundTaskThread):
    def __init__(self,rules_path,bv,uaf):
        self.progress_banner = f"[VulnFanatic] Running the scanner ... "
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.bv = bv
        self.uaf_scan = uaf
        with open(rules_path,'r') as rules_file:
            self.rules = json.load(rules_file)
         
    def run(self):
        # For each rule in self.rules
        function_counter = 0
        xrefs_cache = dict()
        for function in self.rules["functions"]:
            function_counter += 1
            function_refs = get_xrefs_of_symbol(self.bv,function)
            xref_counter = 1 
            # Recursively get all calls with the details
            for xref in function_refs:
                self.progress = f"{self.progress_banner} - Scanning xrefs to function '{function}' ({function_counter}/{len(self.rules['functions'])}):  xref ({xref_counter}/{len(function_refs)})"
                xref_counter += 1
                fun_trace = FunctionTracer(self.bv,xrefs_cache)
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
                                    #log_info(variant["confidence"] + " " +f'{test_case["name"]}')
                                    break
        if self.uaf_scan:
            free = FreeScanner2(self.bv)
            free.start()
    
    def create_description(self,sources):
        desc = ""
        src_counter = 1
        for src in sources:
            desc += f"Source #{src_counter}:\n"
            if "param" in src["var_type"]:
                desc += f"Parameter {str(src['var'])} of function {src['function_name']} source of parameter #{src['param']} ({src['param_var']})\n"
            elif "stack" in src["var_type"]:
                desc += f"Stack variable {str(src['var'])} defined at {hex(src['def_instruction_address'])} source of parameter #{src['param']} ({src['param_var']})\n"
            if len(src["function_calls"]) > 0:
                desc += f"Function calls affecting parameter #{src['param']} ({src['param_var']}):\n"
                for fun_call in src["function_calls"]:
                    desc += f"\t - {fun_call['function_name']}@{fun_call['at_function_name']}\n"
            src_counter += 1
        desc += "\n"
        return desc