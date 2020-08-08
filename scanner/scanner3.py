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
        "exported: : True,
        "if_dependant": True,
        "affected_by": ["strlen,toa,toi"],
        "affected_by_without_if": ["alloc"]
    }

On lighttpd competing against 431
'''
# TODO run UAF scanner
# CFM (v2): [*] Completed in 6746.591761827469 and flaged 1428 places out of 3510 checked.
#           [*] Completed in 8136.563944816589 and flaged 1428 places out of 3510 checked.
#           [*] Completed in 4508.443830013275 and flaged 1428 places out of 3510 checked.

# Lighttpd (v2): [*] Completed in 460.0162880420685 and flaged 21 places out of 62 checked.

# Libxml [*] Completed in 40274.60975623131 and flaged 50 places out of 327 checked.

# Libnetwork: [*] Completed in 9947.95410990715 and flaged 52 places out of 1397 checked.




# Version 3:
# CFM: [*] Done in 5470.578544139862 seconds and marked 743 out of 3291
#      [*] Done in 8878.285166025162 seconds and marked 743 out of 3291
#      [*] Done in 7919.742606878281 seconds and marked 759 out of 3291
#      [*] Done in 10391.178053855896 seconds and marked 773 out of 3323
#      [*] Done in 5077.696810007095 seconds and marked 1001 out of 3323

# Lighttpd: [*] Done in 814.2151880264282 seconds and marked 13 out of 62

# Libxml: [*] Done in 1523.0357477664948 seconds and marked 33 out of 314


# Sandbox: [*] Done in 289.77969193458557 seconds and marked 6 out of 69

# Libnetwork: [*] Done in 2955.574746131897 seconds and marked 61 out of 1086







class Scanner3(BackgroundTaskThread):
    def __init__(self,bv):
        self.progress_banner = f"[VulnFanatic] Running the scanner ..."
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.current_view = bv
        self.xrefs_cache = dict()
        self.marked = 0
        with open(os.path.dirname(os.path.realpath(__file__)) + "/rules3.json",'r') as rules_file:
            self.rules = json.load(rules_file)

    def run(self):
        start = time.time()
        total_xrefs = 0
        for function in self.rules["functions"]:
            function_refs = self.get_function_xrefs(function["function_name"])
            xrefs_count = len(function_refs)
            total_xrefs += xrefs_count
            xref_counter = 0
            for xref in function_refs:
                self.evaluate_results(self.trace(xref,function["trace_params"]),function["function_name"],xref)
                xref_counter += 1
                self.progress = f"{self.progress_banner} checking XREFs of function {function['function_name']} ({round((xref_counter/xrefs_count)*100)}%) - {xref_counter}/{xrefs_count}"
        log_info(f"[*] Done in {time.time()-start} seconds and marked {self.marked} out of {total_xrefs}")

    def evaluate_results(self,trace,function_name,xref):
        # For each level of confidence
        # Go through requirements and comapre them with trace[key]
        # if all param requirments of a confidence level are met mark as an issue an go to next one
        confidence = ["High","Medium","Low","Info"]
        for test in self.rules["test_cases"]:
            if function_name in test["functions"]:
                for conf in confidence:
                    try:
                        current_confidence = test["checks"][conf]
                    except KeyError:
                        continue
                    for cur_rule in current_confidence:
                        matches = True
                        keys = []
                        for par_key in cur_rule:
                            if int(par_key) < 0:
                                keys = []
                                current_rule = cur_rule.copy()
                                for key in trace:
                                    if int(key) >= abs(int(par_key)):
                                        keys.append(key)
                                        current_rule[key] = cur_rule[par_key].copy()
                            else:
                                keys = [par_key]
                                current_rule = cur_rule.copy()
                            for param_key in keys:
                                for check_key in current_rule[param_key]:
                                    # This takes the approach that if anything is false, break
                                    if type(current_rule[param_key][check_key]) is list:
                                        if check_key == "not_affected_by":
                                            if self.is_in_array(trace[param_key]["affected_by"],current_rule[param_key][check_key]):
                                                matches = False
                                                break
                                        elif not self.is_in_array(trace[param_key][check_key],current_rule[param_key][check_key]):
                                            matches = False
                                            break
                                    else:
                                        if not trace[param_key][check_key] == current_rule[param_key][check_key]:
                                            matches = False
                                            break
                        if matches:
                            self.marked += 1
                            details = "dummy"
                            tag = xref.function.source_function.create_tag(self.current_view.tag_types["[VulnFanatic] "+conf], f'{test["name"]}: {test["details"]}\n {details}', True)
                            xref.function.source_function.add_user_address_tag(xref.address, tag)
                            break
                    if matches:
                        break


    def is_in_array(self,a,b):
        #for item_a in a:
        tmp = str(a)
        for item_b in b:
            if item_b in tmp:
                return True
        return False

    def trace(self,xref,params_arg):
        # Get list of isntructions
        hlil_instructions = list(xref.function.instructions)
        trace_struct = {}
        home_block = f"{xref.il_basic_block.start}@{xref.function.source_function.name}"
        params = params_arg.copy()
        # Params loop
        # Using while as negative numbers meand look for param from index
        while params:
            p = params.pop()
            trace_struct[str(p)] = {
                "is_constant": False,
                "constant_value": [],
                "exported": False,
                "if_dependant": False,
                "affected_by": [],
                "affected_by_in_same_block": []
            }
            # Negative number in params means that all parameters from that index should be traced (including the index)
            if p < 0:
                for t_p in range(abs(p),len(xref.params)):
                    params.append(t_p)
                continue
            if p < len(xref.params):
                param_vars = self.prepare_relevant_variables(xref.params[p])
                if not param_vars["vars"] and (xref.params[p].operation == HighLevelILOperation.HLIL_CONST or xref.params[p].operation == HighLevelILOperation.HLIL_CONST_PTR):
                    try:
                        value = self.current_view.get_string_at(xref.params[p].constant).value
                    except:
                        value = hex(xref.params[p].constant)
                    # handle constant here
                    trace_struct[str(p)]["is_constant"] = True
                    trace_struct[str(p)]["constant_value"].append(value)
                    continue
                # The main tracing loop
                blocks = [{"block":xref.il_basic_block,"start":xref.il_basic_block.start-1,"end":xref.instr_index,"param_vars":param_vars.copy()}]
                previous_function = xref.il_basic_block.function.name
                visited_blocks = [f"{xref.il_basic_block.start}@{previous_function}"]
                while blocks:
                    current_block = blocks.pop()
                    if previous_function != current_block["block"].function.name:
                        hlil_instructions = list(current_block["block"].function.hlil.instructions)
                        previous_function = current_block['block'].function.name
                    # Previous function here always holds current function name
                    #log_info(f"{current_block['block'].start}@{previous_function}")
                    params_to_check = []
                    try:
                        for param in current_block["param_vars"]["possible_values"]:
                            if re.search(param,str(hlil_instructions[current_block["start"]:current_block["end"]+1])):
                                params_to_check.append(param)
                    except:
                        pass
                    if params_to_check:
                        for index in range(current_block["end"],current_block["start"],-1):
                            if index < len(hlil_instructions):
                                instruction = hlil_instructions[index]
                                for param in params_to_check:
                                    try:
                                        if re.search(param,str(instruction)):
                                            # found instruction where the desired parameter is used
                                            # Check if it is part of an if:
                                            if instruction.operation == HighLevelILOperation.HLIL_IF:
                                                trace_struct[str(p)]["if_dependant"] = True
                                            # Constant check
                                            if instruction.operation == HighLevelILOperation.HLIL_ASSIGN or instruction.operation == HighLevelILOperation.HLIL_VAR_INIT:
                                                if instruction.src.operation == HighLevelILOperation.HLIL_CONST or instruction.src.operation == HighLevelILOperation.HLIL_CONST_PTR:
                                                    try:
                                                        value = self.current_view.get_string_at(instruction.src.constant).value
                                                    except:
                                                        value = hex(instruction.src.constant)
                                                    # handle constant here
                                                    trace_struct[str(p)]["is_constant"] = True
                                                    trace_struct[str(p)]["constant_value"].append(value)
                                            # Check if it is part of a call:
                                            calls = extract_hlil_operations(instruction.function,[HighLevelILOperation.HLIL_CALL],specific_instruction=instruction)
                                            for call in calls:
                                                if re.search(param,str(call.params)) and call != xref:
                                                    trace_struct[str(p)]["affected_by"].append(str(call.dest))
                                                    if f"{instruction.il_basic_block.start}@{previous_function}" == home_block:
                                                        trace_struct[str(p)]["affected_by_in_same_block"].append(str(call.dest))
                                                elif (instruction.operation == HighLevelILOperation.HLIL_ASSIGN or 
                                                instruction.operation == HighLevelILOperation.HLIL_VAR_INIT) and re.search(param,str(instruction.dest)):
                                                    # Not in the parameter so check if not assigned with the return value
                                                    trace_struct[str(p)]["affected_by"].append(str(call.dest))
                                                    if f"{instruction.il_basic_block.start}@{previous_function}" == home_block:
                                                        trace_struct[str(p)]["affected_by_in_same_block"].append(str(call.dest))
                                    except re.error:
                                        pass
                                        #log_warn("Regex error due to wrong variable mapping in Binary Ninja: Issue #1864")

                    # Add preceeding blocks
                    if current_block["block"].incoming_edges:
                        for edge in current_block["block"].incoming_edges:
                            if f"{edge.source.start}@{previous_function}" not in visited_blocks:
                                visited_blocks.append(f"{edge.source.start}@{previous_function}")
                                blocks.append({
                                    "block":edge.source,
                                    "start":edge.source.start-1,
                                    "end":edge.source.end-1,
                                    "param_vars":current_block["param_vars"]
                                    })
                    else:
                        # Check of param_vars["vars"] contains arg and look further and mark exported function params where applicable
                        for v in param_vars["vars"]:
                            if v in current_block["block"].function.parameter_vars:
                                for sym in self.current_view.get_symbols_of_type(SymbolType.FunctionSymbol):
                                    if sym.binding == SymbolBinding.GlobalBinding and sym.name == current_block["block"].function.name:
                                        # Exported function
                                        trace_struct[str(p)]["exported"] = True
                                par_index = list(current_block["block"].function.parameter_vars).index(v)
                                xrefs_to_follow = self.get_function_xrefs(current_block["block"].function.name)
                                for x2f in xrefs_to_follow:
                                    if par_index < len(list(x2f.params)) and not f"{x2f.il_basic_block.start}@{x2f.function.source_function.name}" in visited_blocks:
                                        x2f_param_vars = self.prepare_relevant_variables(x2f.params[par_index])
                                        visited_blocks.append(f"{x2f.il_basic_block.start}@{x2f.function.source_function.name}")
                                        blocks.append({
                                            "block":x2f.il_basic_block,
                                            "start":x2f.il_basic_block.start-1,
                                            "end":x2f.instr_index-1,
                                            "param_vars":x2f_param_vars
                                            })
        #log_info(str(trace_struct))
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
                if (d.operation == HighLevelILOperation.HLIL_VAR_INIT or d.operation == HighLevelILOperation.HLIL_ASSIGN) and type(d.src.postfix_operands[0]) == Variable and d.src.postfix_operands[0] not in vars["vars"]:
                    tmp_possible.append(str(d.src))
                    vars["vars"].append(d.src.postfix_operands[0])
                    param_vars.append(d.src.postfix_operands[0])
                elif (d.operation == HighLevelILOperation.HLIL_VAR_INIT or d.operation == HighLevelILOperation.HLIL_ASSIGN) and d.src.operation == HighLevelILOperation.HLIL_CALL:
                    # Handle assignments from calls
                    for param in d.src.params:
                        if type(param.postfix_operands[0]) == Variable and param.postfix_operands[0] not in vars["vars"]:
                            tmp_possible.append(str(param))
                            vars["vars"].append(param.postfix_operands[0])
                            param_vars.append(param.postfix_operands[0])
                elif d.operation == HighLevelILOperation.HLIL_VAR and str(d) not in tmp_possible:
                    tmp_possible.append(str(d))
                    vars["vars"].append(d.var)
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
  
    def get_function_xrefs(self,fun_name):
        try:
            return self.xrefs_cache[fun_name]
        except KeyError:
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
                            calls = extract_hlil_operations(instruction.function,[HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL],specific_instruction=instruction)
                            for call in calls:
                                if function_name == str(call.dest) and call not in xrefs and call.params:
                                    xrefs.append(call)
            
            #if not fun_name in self.xrefs_cache:
            self.xrefs_cache[fun_name] = xrefs.copy()
            return xrefs
    

class fun_help():
    def __init__(self,address):
        self.address = address