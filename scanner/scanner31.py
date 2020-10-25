from binaryninja import *
import re
import json
from .free_scanner3 import FreeScanner3
from ..utils.utils import extract_hlil_operations
#import time

class Scanner31(BackgroundTaskThread):
    def __init__(self,bv):
        self.progress_banner = f"[VulnFanatic] Running the scanner ..."
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.current_view = bv
        self.xrefs_cache = dict()
        #self.marked = 0
        #self.high, self.medium, self.low, self.info = 0,0,0,0
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
                if self.cancelled:
                    return
                self.evaluate_results(self.trace(xref,function["trace_params"]),function["function_name"],xref)
                xref_counter += 1
                self.progress = f"{self.progress_banner} checking XREFs of function {function['function_name']} ({round((xref_counter/xrefs_count)*100)}%)"
        #log_info(f"[*] Vuln scan done in {time.time() - start} and marked {self.marked} out of {total_xrefs} checked.\nHigh: {self.high}\nMedium: {self.medium}\nLow: {self.low}\nInfo: {self.info}")
        free = FreeScanner3(self.current_view)
        free.start()

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
                            if par_key == "return":
                                keys = ["return"]
                                current_rule = cur_rule.copy()
                            else:
                                if int(par_key) < 0:
                                    keys = []
                                    current_rule = cur_rule.copy()
                                    for key in trace:
                                        if key != "return" and int(key) >= abs(int(par_key)):
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
                                    elif type(current_rule[param_key][check_key]) is dict:
                                        if check_key == "not_affected_by":
                                            if self.params_match(trace[param_key]["affected_by"],current_rule[param_key][check_key]):
                                                matches = False
                                                break
                                        else:
                                            if not self.params_match(trace[param_key][check_key],current_rule[param_key][check_key]):
                                                matches = False
                                                break
                                    else:
                                        if not trace[param_key][check_key] == current_rule[param_key][check_key]:
                                            matches = False
                                            break
                        if matches:
                            '''if conf == "High":
                                self.high += 1
                            elif conf == "Medium":
                                self.medium += 1
                            elif conf == "Low":
                                self.low += 1
                            else:
                                self.info += 1
                            self.marked += 1'''
                            tag = xref.function.source_function.create_tag(self.current_view.tag_types["[VulnFanatic] "+conf], f'{test["name"]}: {test["details"]}\n', True)
                            xref.function.source_function.add_user_address_tag(xref.address, tag)
                            break
                    if matches:
                        break

    def params_match(self,trace,rule):
        # TRACE: {"sprintf":[{"0":"TRACKED","1":"%s"},{"0":"DYNAMIC","1":"%d"}],"strcpy":[...]}
        # RULE:  {"sprintf":{"0":"TRACKED","1":"%s"},"strcpy":{ ... }}
        for rule_function in rule:
            for trace_function in trace:
                if rule_function in trace_function:
                    match = True
                    for instance in trace[trace_function]:
                        for par in instance:
                            try:
                                if not rule[rule_function][par] in instance[par]:
                                    match = False
                            except KeyError:
                                if rule[rule_function] == {}:
                                    # In case we dont care about parameters
                                    return True
                                elif par == "return":
                                    pass
                                else:
                                    # Cases with negative params
                                    matches_any = False
                                    for trace_item in rule[rule_function]:
                                        if type(trace_item) is int and int(trace_item) < 0:
                                            for param_index in range(int(par),len(instance)):
                                                if rule[rule_function][trace_item] in instance[str(param_index)]:
                                                    matches_any = True
                                            if not matches_any:
                                                match = False
                        if match:
                            return True
        return False


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
                "affected_by": {},
                "affected_by_in_same_block": {},
                "if_checked": True
            }
            if p == "return":
                # At this point only test case for return we have is whether it is if checked
                trace_struct[str(p)]["if_checked"] = self.check_return_for_ifs(xref,hlil_instructions)
                continue
            # Negative number in params means that all parameters from that index should be traced (including the index)
            if p < 0:
                for t_p in range(abs(p),len(xref.params)):
                    params.append(t_p)
                continue
            if p < len(xref.params):
                if (xref.params[p].operation == HighLevelILOperation.HLIL_CONST or xref.params[p].operation == HighLevelILOperation.HLIL_CONST_PTR):
                    try:
                        value = self.current_view.get_string_at(xref.params[p].constant).value
                    except:
                        value = hex(xref.params[p].constant)
                    # handle constant here
                    trace_struct[str(p)]["is_constant"] = True
                    trace_struct[str(p)]["constant_value"].append(value)
                    continue
                param_vars = self.prepare_relevant_variables(xref.params[p])
                # The main tracing loop
                blocks = [{"block":xref.il_basic_block,"start":xref.il_basic_block.start-1,"end":xref.instr_index,"param_vars":param_vars.copy()}]
                previous_function = xref.il_basic_block.function.name
                hlil_instructions = list(xref.il_basic_block.function.hlil.instructions)
                visited_blocks = [f"{xref.il_basic_block.start}@{previous_function}"]
                while blocks:
                    current_block = blocks.pop()
                    if previous_function != current_block["block"].function.name:
                        hlil_instructions = list(current_block["block"].function.hlil.instructions)
                        previous_function = current_block['block'].function.name

                    # Previous function here always holds current function name
                    params_to_check = current_block["param_vars"]["possible_values"]
                    #params_to_check = []
                    #try:
                    #    for param in current_block["param_vars"]["possible_values"]:
                    #        if re.search(param,str(hlil_instructions[current_block["start"]:current_block["end"]+1])):
                    #            params_to_check.append(param)
                    #except:
                    #    pass
                    #if params_to_check:
                    for index in range(current_block["end"],current_block["start"],-1):
                        if index < len(hlil_instructions):
                            instruction = hlil_instructions[index]
                            for param in params_to_check:
                                if self.is_in_operands(param,self.expand_postfix_operands(instruction)):
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
                                        if call != xref:
                                            if self.is_in_operands(param,self.expand_postfix_operands(call.params)):
                                                params_dict = {}
                                                call_param_index = 0
                                                for call_param in call.params:
                                                    param_value = ""
                                                    if call_param.operation == HighLevelILOperation.HLIL_CONST or call_param.operation == HighLevelILOperation.HLIL_CONST_PTR:
                                                        try:
                                                            param_value = self.current_view.get_string_at(call_param.constant).value
                                                        except:
                                                            param_value = hex(call_param.constant)
                                                    if self.is_in_operands(param,self.expand_postfix_operands(call_param)):
                                                        param_value = "TRACKED"
                                                    if not param_value:
                                                        param_value = "DYNAMIC_VALUE"
                                                    params_dict[str(call_param_index)] = param_value
                                                    call_param_index += 1
                                                if instruction.operation == HighLevelILOperation.HLIL_ASSIGN_UNPACK or instruction.operation == HighLevelILOperation.HLIL_ASSIGN or instruction.operation == HighLevelILOperation.HLIL_VAR_INIT:
                                                    params_dict["return"] = "DYNAMIC_VALUE"
                                                try:
                                                    trace_struct[str(p)]["affected_by"][str(call.dest)].append(params_dict)
                                                except KeyError:
                                                    trace_struct[str(p)]["affected_by"][str(call.dest)] = [params_dict]
                                                if f"{instruction.il_basic_block.start}@{previous_function}" == home_block:
                                                    try:
                                                        trace_struct[str(p)]["affected_by_in_same_block"][str(call.dest)].append(params_dict)
                                                    except KeyError:
                                                        trace_struct[str(p)]["affected_by_in_same_block"][str(call.dest)] = [params_dict]
                                            elif (instruction.operation == HighLevelILOperation.HLIL_ASSIGN or
                                            instruction.operation == HighLevelILOperation.HLIL_VAR_INIT) and self.is_in_operands(param,self.expand_postfix_operands(instruction.dest)):
                                                params_dict = {}
                                                call_param_index = 0
                                                for call_param in call.params:
                                                    param_value = ""
                                                    if call_param.operation == HighLevelILOperation.HLIL_CONST or call_param.operation == HighLevelILOperation.HLIL_CONST_PTR:
                                                        try:
                                                            param_value = self.current_view.get_string_at(call_param.constant).value
                                                        except:
                                                            param_value = hex(call_param.constant)
                                                    else:
                                                        param_value = "DYNAMIC_VALUE"
                                                    params_dict[str(call_param_index)] = param_value
                                                    call_param_index += 1
                                                params_dict["return"] = "TRACKED"
                                                # Not in the parameter so check if not assigned with the return value
                                                try:
                                                    trace_struct[str(p)]["affected_by"][str(call.dest)].append(params_dict)
                                                except KeyError:
                                                    trace_struct[str(p)]["affected_by"][str(call.dest)] = [params_dict]
                                                if f"{instruction.il_basic_block.start}@{previous_function}" == home_block:
                                                    try:
                                                        trace_struct[str(p)]["affected_by_in_same_block"][str(call.dest)].append(params_dict)
                                                    except KeyError:
                                                        trace_struct[str(p)]["affected_by_in_same_block"][str(call.dest)] = [params_dict]
                    # Add preceeding blocks
                    if current_block["block"].incoming_edges:
                        for edge in current_block["block"].incoming_edges:
                            if f"{edge.source.start}@{previous_function}" not in visited_blocks:
                                visited_blocks.append(f"{edge.source.start}@{previous_function}")
                                blocks.append({
                                    "block":edge.source,
                                    "start":edge.source.start-1,
                                    "end":edge.source.end-1,
                                    "param_vars":current_block["param_vars"].copy()
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
                                            "param_vars":x2f_param_vars.copy()
                                            })
        return trace_struct


    def check_return_for_ifs(self,xref,hlil_instructions):
        call_instruction = hlil_instructions[xref.instr_index]
        ret_var = []
        if call_instruction.operation == HighLevelILOperation.HLIL_IF:
            return True
        elif call_instruction.operation == HighLevelILOperation.HLIL_ASSIGN:
            try:
                ret_var = [call_instruction.dest.postfix_operands]
            except:
                ret_var = [[call_instruction.dest]]
        elif call_instruction.operation == HighLevelILOperation.HLIL_VAR_INIT:
            ret_var = [[call_instruction.dest]]
        elif call_instruction.operation == HighLevelILOperation.HLIL_ASSIGN_UNPACK:
            for d in call_instruction.dest:
                ret_var.append([d.var])
        else:
            return False
        # get index of last instruction in current block
        last_inst = hlil_instructions[xref.il_basic_block.end - 1]
        for ret in ret_var:
            if last_inst.operation == HighLevelILOperation.HLIL_IF and self.is_in_operands(ret,self.expand_postfix_operands(last_inst)):
                return True
        return False

    # This will take into account only variables that are preceeding the relevant XREF
    def prepare_relevant_variables(self,param):
        vars = {
            "possible_values": [],
            "vars": [],
            "orig_vars": {},
            "param_vars": []
        }
        hlil_instructions = list(param.function.instructions)
        params = []
        param_var_dict = {}
        calls = extract_hlil_operations(param.function,[HighLevelILOperation.HLIL_CALL],specific_instruction=param)
        if calls:
            for call in calls:
                params.extend(call.params)
        else:
            params.append(param)
        for param in params:
            param_vars_hlil = extract_hlil_operations(param.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=param)
            param_vars = []
            original_value = self.expand_postfix_operands(param)
            vars["possible_values"].append(original_value)
            for p in param_vars_hlil:
                vars["orig_vars"][str(p)] = []
                param_var_dict[str(p)] = p.var
                param_vars.append(p.var)
                vars["param_vars"].append(p.var)
            for param_var in vars["orig_vars"]:
                # For each of the original variables find its possible alternatives
                for var in param_vars:
                    if var not in vars["orig_vars"][param_var]:
                        vars["orig_vars"][param_var].append(var)
                    if var not in vars["vars"]:
                        vars["vars"].append(var)
                    definitions = param.function.get_var_definitions(var)
                    # Also uses are relevant
                    definitions.extend(param.function.get_var_uses(var))
                    for d in definitions:
                        if d.instr_index != param.instr_index and var in self.expand_postfix_operands(d):
                            current_instruction = hlil_instructions[d.instr_index]
                            try:
                                is_in_dest = var in current_instruction.dest.postfix_operands
                            except:
                                try:
                                    is_in_dest = var == current_instruction.dest
                                except:
                                    # No dest
                                    continue
                            try:
                                if not is_in_dest and current_instruction.operation == HighLevelILOperation.HLIL_VAR_INIT:
                                    vars["orig_vars"][param_var].append(current_instruction.dest)
                                    if current_instruction.dest not in param_vars:
                                        param_vars.append(current_instruction.dest)
                                elif is_in_dest and current_instruction.operation == HighLevelILOperation.HLIL_ASSIGN:
                                    for v in extract_hlil_operations(d.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=current_instruction.dest):
                                        if v.var not in vars["orig_vars"][param_var]:
                                            vars["orig_vars"][param_var].append(v.var)
                                            param_vars.append(v.var)
                                elif is_in_dest and current_instruction.operation == HighLevelILOperation.HLIL_ASSIGN_UNPACK:
                                    for dest_var in current_instruction.dest:
                                        vars["orig_vars"][param_var].append(dest_var.var)
                                        if dest_var.var not in param_vars:
                                            param_vars.append(dest_var.var)
                                elif is_in_dest and current_instruction.src.operation == HighLevelILOperation.HLIL_CALL:
                                    for param in extract_hlil_operations(d.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=current_instruction.src):
                                        if param.var not in vars["orig_vars"][param_var]:
                                            vars["orig_vars"][param_var].append(param.var)
                                            param_vars.append(param.var)
                                elif is_in_dest:
                                    for dest_var in self.expand_postfix_operands(current_instruction.src):
                                        if type(dest_var) is Variable:
                                            vars["orig_vars"][param_var].append(dest_var)
                                            if dest_var not in param_vars:
                                                param_vars.append(dest_var)
                            except:
                                pass
                for v in vars["orig_vars"][param_var]:
                    tmp = [x if x != param_var_dict[param_var] else v for x in original_value]
                    if tmp not in vars["possible_values"]:
                        vars["possible_values"].append(tmp)
        return vars

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
            if fun_name[:2] == "_Z":
                # Handle C++ mangled names
                function_name = re.sub(r'\(.*\)', '', self.current_view.symbols[fun_name].full_name)
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
                                if function_name == str(call.dest) and not self.is_in(call,xrefs) and call.params:
                                    xrefs.append(call)

            #if not fun_name in self.xrefs_cache:
            self.xrefs_cache[fun_name] = xrefs.copy()
            return xrefs

    def is_in(self,item,array):
        for i in array:
            if item is i:
                return True
        return False

    def cleanup_op(self,operands):
        result = []
        b = [0,None,HighLevelILOperationAndSize(HighLevelILOperation.HLIL_STRUCT_FIELD,4)]
        c = [0,None,HighLevelILOperationAndSize(HighLevelILOperation.HLIL_STRUCT_FIELD,8)]
        i = 0
        while i < len(operands):
            if operands[i:i+3] == b or operands[i:i+3] == c:
                i += 3
            elif ((type(operands[i]) is HighLevelILOperationAndSize and operands[i].operation == HighLevelILOperation.HLIL_VAR) or
            (type(operands[i]) is HighLevelILOperationAndSize and operands[i].operation == HighLevelILOperation.HLIL_SX)):
                # Skipping problematic operands
                i += 1
            else:
                result.append(operands[i])
                i += 1
        return result

    def is_in_operands(self,op,operands):
        for i in range(len(operands)-len(op)+1):
            if operands[i:i+len(op)] == op:
                return True
        return False

    def expand_postfix_operands(self,instruction):
        result = []
        if type(instruction) is binaryninja.Variable:
            return [instruction]
        try:
            op = instruction.postfix_operands.copy()
        except:
            op = instruction.copy()
        while op:
            current_op = op.pop(0)
            if type(current_op) is list:
                op = current_op + op
                continue
            try:
                op = current_op.postfix_operands + op
            except:
                result.append(current_op)

        return self.cleanup_op(result)

class fun_help():
    def __init__(self,address):
        self.address = address