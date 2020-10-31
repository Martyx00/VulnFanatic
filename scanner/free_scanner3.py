from binaryninja import *
import re
#import time

class FreeScanner3(BackgroundTaskThread):
    def __init__(self,bv):
        self.current_view = bv
        self.progress_banner = f"[VulnFanatic] Running the scanner ... looking for Use-after-free issues"
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.free_list = ["free","_free","_freea","freea","free_dbg","_free_dbg","free_locale","_free_locale","g_free","operator delete","operator delete[]"]

    def run(self):
        #start = time.time()
        #vuln_counter = 0
        free_xrefs = self.get_xrefs_with_wrappers()
        counter = 1
        total = len(free_xrefs)
        # With all wrappers detected lets do the scan
        for free_xref in free_xrefs:
            self.progress = f"{self.progress_banner} ({round((counter/total)*100)}%)"
            counter += 1
            if self.cancelled:
                return
            if free_xref["param_index"] < len(free_xref["instruction"].params):
                param_vars = free_xref["param_vars"]
                uaf,uaf_if,double,glob = self.scan(free_xref["instruction"],param_vars)
                current_free_xref_obj = {
                    "used_after": uaf,
                    "without_if": uaf_if,
                    "double_free": double,
                    "global_uaf": glob,
                    "struct_free_wrapper": free_xref["struct_free_wrapper"]
                }
                if current_free_xref_obj["double_free"] and current_free_xref_obj["without_if"]:
                    tag = free_xref["instruction"].function.source_function.create_tag(self.current_view.tag_types["[VulnFanatic] Medium"], "Potential Double Free Vulnerability", True)
                    free_xref["instruction"].function.source_function.add_user_address_tag(free_xref["instruction"].address, tag)
                    continue
                elif current_free_xref_obj["double_free"]:
                    tag = free_xref["instruction"].function.source_function.create_tag(self.current_view.tag_types["[VulnFanatic] Low"], "Potential Double Free Vulnerability", True)
                    free_xref["instruction"].function.source_function.add_user_address_tag(free_xref["instruction"].address, tag)
                    continue
                # First process parameter variables
                confidence = ""
                if current_free_xref_obj["used_after"] and current_free_xref_obj["without_if"]:
                    confidence = "Medium"
                elif current_free_xref_obj["used_after"] or (current_free_xref_obj["global_uaf"] and not current_free_xref_obj["struct_free_wrapper"]):
                #elif current_free_xref_obj["used_after"]:
                    confidence = "Low"
                elif current_free_xref_obj["struct_free_wrapper"]:
                    confidence = "Info"
                if confidence:
                    #vuln_counter += 1
                    if confidence == "Info":
                        desc = "Free wrapper worth to investigate."
                    else:
                        desc = "Potential Use-afer-free Vulnerability"
                    tag = free_xref["instruction"].function.source_function.create_tag(self.current_view.tag_types["[VulnFanatic] "+confidence], desc, True)
                    free_xref["instruction"].function.source_function.add_user_address_tag(free_xref["instruction"].address, tag)
        #log_info(f"[*] Free scan done in {time.time() - start} and found {vuln_counter}")

    def scan(self,instruction,param_vars):
        current_hlil_instructions = list(instruction.function.instructions)
        # Check if instruction is in loop so that we know how to proceed with checks further
        in_loop = self.is_in_loop(instruction)
        # Check if param is used after the free call, if not in loop get rid of first instruction
        used_after, used_after_with_if,double, init = self.used_after2(param_vars,instruction,current_hlil_instructions,in_loop)
        return used_after, used_after_with_if, double, init

    def used_after2(self,param_vars,instruction,hlil_instructions,in_loop):
        loops = [HighLevelILOperation.HLIL_DO_WHILE,HighLevelILOperation.HLIL_WHILE,HighLevelILOperation.HLIL_FOR]
        skip_operations = [HighLevelILOperation.HLIL_IF,HighLevelILOperation.HLIL_ASSIGN,HighLevelILOperation.HLIL_VAR_INIT,HighLevelILOperation.HLIL_RET]
        skip_operations.extend(loops)
        uaf = False
        uaf_if = False
        double = False
        blocks = [{"block":instruction.il_basic_block,"start":instruction.instr_index + 1,"end":instruction.il_basic_block.end}]
        loop_pass = False
        initialized = False
        #nested_loops = []
        visited_blocks = []
        global_uaf = False
        init = False
        while blocks:
            initialized = False
            current_block = blocks.pop()
            visited_blocks.append(current_block["start"])
            #if current_block["start"] < len(hlil_instructions) and hlil_instructions[current_block["start"]].operation in loops:
            #    nested_loops.append(current_block["start"])
            if in_loop["in_loop"] and current_block["start"] == in_loop["loop_start"] and loop_pass:
                # Now we are 100% sure that the whole loop was searched throughs
                # This needs to finnish for all paths
                continue
            elif in_loop["in_loop"] and current_block["start"] == in_loop["loop_start"] and not loop_pass:
                loop_pass = True
            # First check all instructions inside current block
            for index in range(current_block["start"],current_block["end"]):
                i = hlil_instructions[index]
                for param in param_vars["possible_values"]:
                    if i:# and i.instr_index != instruction.instr_index:
                        is_in = self.is_in_operands(param,self.expand_postfix_operands(i))
                        if is_in:
                            if (((i.operation == HighLevelILOperation.HLIL_ASSIGN or i.operation == HighLevelILOperation.HLIL_VAR_INIT) 
                            and self.is_in_operands(param,self.expand_postfix_operands(i.dest))) 
                            or (re.search("alloc",str(i)) and is_in)):
                                # Found initialization of the variable
                                initialized = True
                                init = True
                                break
                            if (not i.operation in skip_operations and is_in) or (is_in and i.operation == HighLevelILOperation.HLIL_RET and self.extract_hlil_operation(i.instr,[HighLevelILOperation.HLIL_CALL])):
                                if i.operation == HighLevelILOperation.HLIL_CALL and str(i.dest) in self.free_list:
                                    double = True
                                if self.not_if_dependent(instruction,param_vars):
                                    uaf_if = True
                                uaf = True
                                return uaf, uaf_if, double, global_uaf
            # Add following blocks only if current block have not initialized the variable
            if not initialized:
                for edge in current_block["block"].outgoing_edges:
                    if edge.target.start not in visited_blocks:
                        blocks.append({"block":edge.target,"start":edge.target.start,"end":edge.target.end})
        # Was not initialized but also not used
        # See if source is dereference of constant, this signals use of global variable
        if not init:
            glob = False
            for v in param_vars["param_vars"]:
                if self.is_global_var(v,instruction.function):
                    glob = True
                    break
            refs = self.get_xrefs_to_call([instruction.function.source_function.name])
            for ref in refs:
                in_loop = self.is_in_loop(ref)
                if in_loop["in_loop"] and glob:
                    global_uaf = True
        return uaf, uaf_if, double, global_uaf

    def extract_hlil_operation(self,instruction,operations):
        extracted_operations = []
        if instruction.operation in operations:
            extracted_operations.append(instruction)
        operands_mag = instruction.operands.copy()
        while operands_mag:
            op = operands_mag.pop()
            if type(op) == HighLevelILInstruction and op.instr_index == instruction.instr_index:
                if op.operation in operations:
                    extracted_operations.append(op)
                    operands_mag.extend(op.operands)
                else:
                    operands_mag.extend(op.operands)
            elif type(op) is list:
                for o in op:
                    operands_mag.append(o)
        return extracted_operations

    def is_global_var(self,var,function):
        vars = [var]
        checked_vars = []
        while vars:
            v = vars.pop()
            checked_vars.append(v.name)
            defs = function.get_var_definitions(v)
            for d in defs:
                try:
                    consts = self.extract_hlil_operation(d.instr,[HighLevelILOperation.HLIL_CONST_PTR])
                    for c in consts:
                        if c.parent.operation == HighLevelILOperation.HLIL_DEREF:
                            # Likely a global variable deref
                            return True
                    vs = self.extract_hlil_operation(d.instr,[HighLevelILOperation.HLIL_VAR])
                    for a in vs:
                        if a.var.name not in checked_vars:
                            vars.append(a.var)
                except:
                    pass
        return False

    def cleanup_op(self,operands):
        result = []
        b = [0,None,HighLevelILOperationAndSize(HighLevelILOperation.HLIL_STRUCT_FIELD,4)]
        i = 0
        while i < len(operands):
            if operands[i:i+3] == b:
                i += 3
            elif ((type(operands[i]) is HighLevelILOperationAndSize and operands[i].operation == HighLevelILOperation.HLIL_VAR) or
            (type(operands[i]) is HighLevelILOperationAndSize and operands[i].operation == HighLevelILOperation.HLIL_SX)):
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

    def prepare_relevant_variables(self,param):
        vars = {
            "possible_values": [],
            "orig_vars": {},
            "param_vars": []
        }
        params = []
        param_var_dict = {}
        calls = self.extract_hlil_operation(param,[HighLevelILOperation.HLIL_CALL])
        if calls:
            for call in calls:
                params.extend(call.params)
        else:
            params.append(param)
        for param in params:
            param_vars_hlil = self.extract_hlil_operation(param,[HighLevelILOperation.HLIL_VAR])
            original_value = self.expand_postfix_operands(param)
            vars["possible_values"].append(original_value)
            #param_var_dict = {}
            for p in param_vars_hlil:
                vars["orig_vars"][str(p)] = [p.var]
                param_var_dict[str(p)] = p.var
                vars["param_vars"].append(p.var)
            for param_var in vars["orig_vars"]:
                # For each of the original variables find its possible alternatives
                for var in vars["orig_vars"][param_var]:
                    definitions = param.function.get_var_definitions(var)
                    # Also uses are relevant
                    definitions.extend(param.function.get_var_uses(var))
                    for d in definitions:
                        operands = d.instr.postfix_operands
                        if d.instr_index != param.instr_index and var in operands:
                            operands = d.instr.postfix_operands
                            for op in operands:
                                try:
                                    op.type
                                    if not op in vars["orig_vars"][param_var]:
                                        vars["orig_vars"][param_var].append(op)
                                except:
                                    if type(op) is list:
                                        operands.extend(op)

                for v in vars["orig_vars"][param_var]:
                    tmp = [x if x != param_var_dict[param_var] else v for x in original_value]
                    if tmp not in vars["possible_values"]:
                        vars["possible_values"].append(tmp)
        return vars


    def get_xrefs_with_wrappers(self):
        free_xrefs = []
        for xref in self.get_xrefs_to_call(self.free_list):
            append = True
            if len(xref.params) > 0:
                param_vars = self.prepare_relevant_variables(xref.params[0])
                for var in param_vars["param_vars"]:
                    if var in xref.function.source_function.parameter_vars:
                        wrapper_xrefs = self.get_xrefs_to_call([xref.function.source_function.name])
                        if wrapper_xrefs:
                            for wrapper_xref in wrapper_xrefs:
                                par_index = list(xref.function.source_function.parameter_vars).index(var)
                                try:
                                    free_xrefs.append({
                                        "instruction": wrapper_xref,
                                        "param_index": par_index,
                                        "struct_free_wrapper": False,
                                        "param_vars": self.prepare_relevant_variables(wrapper_xref.params[par_index])
                                    })
                                except:
                                    pass
                        else:
                            # No xrefs -> struct free wrapper???
                            free_xrefs.append({
                                "instruction": xref,
                                "param_index": 0,
                                "struct_free_wrapper": True,
                                "param_vars": param_vars
                            })
                    elif append:
                        free_xrefs.append({
                            "instruction": xref,
                            "param_index": 0, # All the default free calls take just one parameter
                            "struct_free_wrapper": False,
                            "param_vars": param_vars
                        })
                        append = False
        return free_xrefs

    def get_xrefs_to_call(self,function_names):
        altered_names = []
        for f in function_names:
            if f[:4] == "sub_":
                altered_names.append(f"0x{f[4:]}")
            # C++ mangled names
            elif f[:2] == "_Z":
                value = re.sub(r'\(.*\)', '', self.current_view.symbols[f].full_name)
                altered_names.append(value)
                function_names.append(value)
            else:
                altered_names.append(f)
        checked_functions = []
        xrefs = []
        for symbol_name in function_names:
            symbol_item = []
            try:
                symbol_item.extend(self.current_view.symbols[symbol_name]) if type(self.current_view.symbols[symbol_name]) is list else symbol_item.append(self.current_view.symbols[symbol_name])
            except KeyError:
                pass
            try:
                symbol_item.extend(self.current_view.symbols[symbol_name+"@IAT"]) if type(self.current_view.symbols[symbol_name+"@IAT"]) is list else symbol_item.append(self.current_view.symbols[symbol_name+"@IAT"])
            except KeyError:
                pass
            try:
                symbol_item.extend(self.current_view.symbols[symbol_name+"@PLT"]) if type(self.current_view.symbols[symbol_name+"@PLT"]) is list else symbol_item.append(self.current_view.symbols[symbol_name+"@PLT"])
            except KeyError:
                pass
            if symbol_name == "operator delete":
                symbols_mag = [list(self.current_view.symbols.items())] 
                while symbols_mag:
                    current_symbols = symbols_mag.pop()
                    if len(current_symbols) != 1:
                        l = round(len(current_symbols)/2)
                        if "operator delete" in str(current_symbols[l:]):
                            symbols_mag.append(current_symbols[l:])
                        if "operator delete" in str(current_symbols[:l]):
                            symbols_mag.append(current_symbols[:l])
                    else:
                        sym = current_symbols[0][0]
                        if type(self.current_view.symbols[sym]) is list:
                            for item in self.current_view.symbols[sym]:
                                if "operator delete" in item.full_name and item not in symbol_item:
                                    symbol_item.append(item)
                        elif "operator delete" in self.current_view.symbols[sym].full_name and self.current_view.symbols[sym] not in symbol_item:
                            symbol_item.append(self.current_view.symbols[sym])            
            for symbol in symbol_item if type(symbol_item) is list else [symbol_item]:
                for ref in self.current_view.get_code_refs(symbol.address):
                    # Get exact instruction index
                    if ref.function.name in checked_functions:
                        continue
                    else:
                        checked_functions.append(ref.function.name)
                    for instruction in ref.function.hlil.instructions:
                        # For each instruction check if any of the functions we are looking for is called
                        for f in function_names:
                            if f in str(instruction):
                                # Extract the call here
                                calls = self.extract_hlil_operation(instruction,[HighLevelILOperation.HLIL_CALL])
                                for call in calls:
                                    if str(call.dest) in altered_names and not self.is_in(call,xrefs):
                                        xrefs.append(call)
        return xrefs

    def is_in(self,item,array):
        for i in array:
            if item is i:
                return True
        return False
    
    def is_in_loop(self,instruction):
        loop_object = {"loop":None,"in_loop":False}
        parent = instruction.parent
        while parent != None:
            if parent.operation == HighLevelILOperation.HLIL_DO_WHILE or parent.operation == HighLevelILOperation.HLIL_FOR or parent.operation == HighLevelILOperation.HLIL_WHILE:
                loop_object = {"loop":parent,"in_loop":True,"loop_start":parent.il_basic_block.start}
                return loop_object
            parent = parent.parent
        return loop_object

    def not_if_dependent(self,instruction,param_vars):
        if_dep = True
        parent = instruction.parent
        while parent != None:
            if parent.operation == HighLevelILOperation.HLIL_IF:
                for param in param_vars["possible_values"]:
                    if self.is_in_operands(param,self.expand_postfix_operands(parent)):
                        if_dep = False 
            parent = parent.parent
        return if_dep