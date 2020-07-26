from binaryninja import *
import re
import json
from .free_scanner2 import FreeScanner2
from ..utils.utils import extract_hlil_operations
import time


'''
 "0":{
        "constant": False,
        "user_controled": True,
        "param_of_exported: : True,
        "if_dependant": True,
        "affected_by": ["strlen,toa,toi"],
        "affected_by_without_if": ["alloc"]
    }

On lighttpd competing against 431
'''

class Scanner3(BackgroundTaskThread):
    def __init__(self,bv):
        self.progress_banner = f"[VulnFanatic] Running the scanner ... "
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.current_view = bv
        with open(os.path.dirname(os.path.realpath(__file__)) + "/rules3.json",'r') as rules_file:
            self.rules = json.load(rules_file)

    def run(self):
        start = time.time()
        function_counter = 0
        xrefs_cache = dict()
        for function in self.rules["functions"]:
            function_counter += 1
            function_refs = self.get_function_xrefs(function["function_name"])
            for xref in function_refs:
                self.trace(xref,function["trace_params"])
                xref_counter = 1

        log_info(f"[*] Done in {time.time()-start}")

    def trace(self,xref,params_arg):
        # Get list of isntructions
        hlil_instructions = list(xref.function.instructions)
        trace_struct = {}
        home_block = xref.il_basic_block.start
        params = params_arg.copy()
        # Params loop
        # Using while as negative numbers meand look for param from index
        while params:
            p = params.pop()
            trace_struct[str(p)] = {
                "constant": False,
                "user_controlled": False,
                "param_of_exported": False,
                "if_dependant": True,
                "affected_by": [],
                "affected_by_in_same_block": []
            }
            # Negative number in params means that all parameters from that index should be traced (including the index)
            if p < 0:
                for t_p in range(abs(p),len(xref.params)):
                    params.append(t_p)
            # TODO is peresence of any parameter in param_vars["vars"] a good indicator of param source?
            param_vars = self.prepare_relevant_variables(xref.params[p])
            if not param_vars["vars"]:
                # handle constant here
                trace_struct[str(p)]["constant"] = xref.params[p]
                continue
            #log_info(str(param_vars))
            # The main tracing loop
            blocks = [{"block":xref.il_basic_block,"start":xref.il_basic_block.start-1,"end":xref.instr_index-1,"param_vars":param_vars.copy(),"visited_blocks":[]}]
            previous_function = xref.il_basic_block.function.name
            while blocks:
                current_block = blocks.pop()
                if previous_function != current_block["block"].function.name:
                    hlil_instructions = list(current_block["block"].function.hlil.instructions)
                    log_info(f"SWITCHING FUNCTION TO {current_block['block'].function.name}")
                    previous_function = current_block['block'].function.name
                # Previous functio nhere always holds current functio name
                current_block["visited_blocks"].append(f"{current_block['start']}@{previous_function}")
                for index in range(current_block["end"],current_block["start"],-1):
                    if index < len(hlil_instructions):
                        instruction = hlil_instructions[index]
                        for param in current_block["param_vars"]["possible_values"]:
                            if re.search(param,str(instruction)):
                                # found instruction where the desired parameter is used
                                # Check if it is part of an if:
                                if instruction.operation == HighLevelILOperation.HLIL_IF:
                                    trace_struct[str(p)]["if_dependant"] = True
                                # Check if it is part of a call:
                                calls = extract_hlil_operations(instruction.function,[HighLevelILOperation.HLIL_CALL],specific_instruction=instruction)
                                for call in calls:
                                    if re.search(param,str(call.params)):
                                        trace_struct[str(p)]["affected_by"].append(call.dest)
                                        if instruction.il_basic_block.start == home_block:
                                            trace_struct[str(p)]["affected_by_in_same_block"].append(call.dest)
                                    elif (instruction.operation == HighLevelILOperation.HLIL_ASSIGN or 
                                    instruction.operation == HighLevelILOperation.HLIL_VAR_INIT) and re.search(param,str(instruction.dest)):
                                        # Not in the parameter so check if not assigned with the return value
                                        trace_struct[str(p)]["affected_by"].append(call.dest)
                                        if instruction.il_basic_block.start == home_block:
                                            trace_struct[str(p)]["affected_by_in_same_block"].append(call.dest)

                # Add preceeding blocks
                if current_block["block"].incoming_edges:
                    for edge in current_block["block"].incoming_edges:
                        if f"{edge.source.start}@{previous_function}" not in current_block["visited_blocks"]:
                            blocks.append({
                                "block":edge.source,
                                "start":edge.source.start-1,
                                "end":edge.source.end-1,
                                "param_vars":current_block["param_vars"],
                                "visited_blocks":current_block["visited_blocks"]
                                })
                else:
                    # TODO No incoming edges -> likely start of the function
                    # Check of param_vars["vars"] contains arg and look further and mark exported function params where applicable
                    for v in param_vars["vars"]:
                        if v in current_block["block"].function.parameter_vars:
                            par_index = list(current_block["block"].function.parameter_vars).index(v)
                            # TODO
                            # Visited blocks need to be copied! and contain function name
                            # param_vars freshly taken from the xref
                            # Handle expored also!
                            log_info("FOUND PARAMS")
                            # TODO XREFS CACHE
                            xrefs_to_follow = self.get_function_xrefs(current_block["block"].function.name)
                            for x2f in xrefs_to_follow:
                                x2f_param_vars = self.prepare_relevant_variables(x2f.params[par_index])
                                blocks.append({
                                    "block":x2f.il_basic_block,
                                    "start":x2f.il_basic_block.start-1,
                                    "end":x2f.instr_index-1,
                                    "param_vars":x2f_param_vars,
                                    "visited_blocks":current_block["visited_blocks"].copy()
                                    })
                    pass
        if xref.function.source_function.name == "_vuln_malloc":
        #log_info(f"{str(xref)}@{xref.function.source_function.name}")
            log_info(str(trace_struct))
        return trace_struct
            

    # This will take into account only variables that are preceeding the relevant XREF
    def prepare_relevant_variables(self,param):
        param_vars_hlil = extract_hlil_operations(param.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=param)
        param_vars = []
        for p in param_vars_hlil:
            param_vars.append(p.var)
        vars = {
            "possible_values": [],
            "vars": [],
            "orig_vars": []
        }
        tmp_possible = [str(param)]
        for var in param_vars:
            if var not in vars["vars"]:
                vars["vars"].append(var)
                vars["orig_vars"].append(var)
            definitions = param.function.get_var_definitions(var)
            # Also uses are relevant
            definitions.extend(param.function.get_var_uses(var))
            for d in definitions:
                if (d.operation == HighLevelILOperation.HLIL_VAR_INIT or d.operation == HighLevelILOperation.HLIL_ASSIGN)and type(d.src.postfix_operands[0]) == Variable and d.src.postfix_operands[0] not in vars["vars"]:
                    val = str(param).replace(str(var),str(d.src.postfix_operands[0]))
                    #tmp_possible.append(val)
                    tmp_possible.append(str(d.src))
                    vars["vars"].append(d.src.postfix_operands[0])
                    param_vars.append(d.src.postfix_operands[0])
        for val in tmp_possible:
            tmp_val = val
            positions = [(m.start(0), m.end(0)) for m in re.finditer(r':\d+\.\w+', val)]
            for pos in positions:
                tmp_val = val[0: pos[0]:] + val[pos[1]::]
            tmp_val = re.escape(tmp_val)
            for v in vars["vars"]:
                # Lol but worth a try :D
                tmp_val = tmp_val.replace(str(v),str(v)+"(:\\d+\\.\\w+)?\\b")
            vars["possible_values"].append(tmp_val)        
        return vars
    
    # Can this be copied?
    def not_if_dependent(self,instruction,param_vars):
        pass

    # TODO XREFS cache
    def get_function_xrefs(self,fun_name):
        checked_functions = []
        xrefs = []
        symbol_item = []
        function_name = fun_name
        if function_name[:4] == "sub_":
            symbol_item.append(fun_help(int("0x"+function_name[4:],16)))
            function_name = "0x"+function_name[4:]
        else:
            try:
                symbol_item.extend(self.current_view.symbols[function_name]) if type(self.current_view.symbols[function_name]) is list else symbol_item.append(self.current_view.symbols[function_name])
            except KeyError:
                pass
            try:
                symbol_item.extend(self.current_view.symbols[function_name+"@IAT"]) if type(self.current_view.symbols[function_name+"@IAT"]) is list else symbol_item.append(self.current_view.symbols[function_name+"@IAT"])
            except KeyError:
                pass
            try:
                symbol_item.extend(self.current_view.symbols[function_name+"@PLT"]) if type(self.current_view.symbols[function_name+"@PLT"]) is list else symbol_item.append(self.current_view.symbols[function_name+"@PLT"])
            except KeyError:
                pass
        for symbol in symbol_item:
            for ref in self.current_view.get_code_refs(symbol.address):
                # Get exact instruction index
                if ref.function.name in checked_functions:
                    continue
                else:
                    checked_functions.append(ref.function.name)
                for instruction in ref.function.hlil.instructions:
                    # For each instruction check if any of the functions we are looking for is called
                    if function_name in str(instruction):
                        # Extract the call here
                        calls = extract_hlil_operations(instruction.function,[HighLevelILOperation.HLIL_CALL],specific_instruction=instruction)
                        for call in calls:
                            if function_name in str(call.dest) and call not in xrefs:
                                xrefs.append(call)
        return xrefs
    

class fun_help():
    def __init__(self,address):
        self.address = address