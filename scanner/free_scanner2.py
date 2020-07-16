from binaryninja import *
import re
from ..utils.utils import extract_hlil_operations
import time


class FreeScanner2(BackgroundTaskThread):
    def __init__(self,bv):
        self.current_view = bv
        self.progress_banner = f"[VulnFanatic] Running the scanner ... looking for Use-after-free issues"
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.free_list = ["free","_free","_freea","freea","free_dbg","_free_dbg","free_locale","_free_locale","g_free","operator delete"]
        #self.free_list = ["free","_free","_freea","freea","free_dbg","_free_dbg","free_locale","_free_locale"]

    def run(self):
        free_xrefs = self.get_xrefs_with_wrappers()
        counter = 1
        total = len(free_xrefs)
        # With all wrappers detected lets do the scan
        for free_xref in free_xrefs:
            self.progress = f"{self.progress_banner} ({counter}/{total})"
            counter += 1
            if free_xref["param_index"] < len(free_xref["instruction"].params):
                param_vars = self.prepare_relevant_variables(free_xref["instruction"].params[free_xref["param_index"]])
                uaf,uaf_if,double,null_set = self.scan(free_xref["instruction"],param_vars)
                current_free_xref_obj = {
                    "used_after": uaf,
                    "without_if": uaf_if,
                    "double_free": double,
                    "is_set_to_null": null_set,
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
                if current_free_xref_obj["used_after"] and current_free_xref_obj["without_if"] and not current_free_xref_obj["is_set_to_null"]:
                    confidence = "Medium"
                elif current_free_xref_obj["used_after"] and not current_free_xref_obj["is_set_to_null"]:
                    confidence = "Low"
                elif not current_free_xref_obj["is_set_to_null"] and current_free_xref_obj["struct_free_wrapper"]:
                    confidence = "Info"
                if confidence:
                    tag = free_xref["instruction"].function.source_function.create_tag(self.current_view.tag_types["[VulnFanatic] "+confidence], "Potential Use-afer-free Vulnerability", True)
                    free_xref["instruction"].function.source_function.add_user_address_tag(free_xref["instruction"].address, tag)

                #log_info(str(current_free_xref_obj))

    def scan(self,instruction,param_vars):
        current_hlil_instructions = list(instruction.function.instructions)
        # Check if instruction is in loop so that we know how to proceed with checks further
        in_loop = self.is_in_loop(instruction)
        instructions = []
        # Check if param set to null
        is_set_to_null = self.is_set_to_null(instructions,param_vars)
        
        # Check if param is used after the free call, if not in loop get rid of first instruction
        if not in_loop["in_loop"]:
            used_after, used_after_with_if,double = self.used_after2(param_vars,instruction,current_hlil_instructions,in_loop)
        else:
            used_after, used_after_with_if,double = self.used_after2(param_vars,instruction,current_hlil_instructions,in_loop)
        return used_after, used_after_with_if, double, is_set_to_null

    def is_set_to_null(self,instructions,param_vars):
        for i in instructions:
            if i:
                for param in param_vars["possible_values"]:
                    if i.operation == HighLevelILOperation.HLIL_ASSIGN and re.search(param,str(i.dest)):
                        # one of the possible values was found in the instruction which assigns value
                        if (i.src.operation == HighLevelILOperation.HLIL_CONST or i.src.operation == HighLevelILOperation.HLIL_CONST_PTR) and i.src.constant == 0:
                            # Null assgined -> return True
                            return True 
        return False

    def used_after2(self,param_vars,instruction,hlil_instructions,in_loop):
        loops = [HighLevelILOperation.HLIL_DO_WHILE,HighLevelILOperation.HLIL_WHILE,HighLevelILOperation.HLIL_FOR]
        skip_operations = [HighLevelILOperation.HLIL_IF,HighLevelILOperation.HLIL_ASSIGN,HighLevelILOperation.HLIL_VAR_INIT]
        skip_operations.extend(loops)
        uaf = False
        uaf_if = False
        double = False
        blocks = [{"block":instruction.il_basic_block,"start":instruction.instr_index + 1,"end":instruction.il_basic_block.end}]
        loop_pass = False
        #nested_loops = []
        visited_blocks = []
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
                    if i and i.instr_index != instruction.instr_index:
                        if (i.operation == HighLevelILOperation.HLIL_ASSIGN and re.search(param,str(i.dest)) or 
                        i.operation == HighLevelILOperation.HLIL_VAR_INIT and re.search(param,str(i.dest))):
                            # Found initialization of the variable
                            initialized = True
                            break
                        if (re.search(param,str(i)) and not i.operation in skip_operations):
                            if i.operation == HighLevelILOperation.HLIL_CALL and str(i.dest) in self.free_list:
                                double = True
                            if self.not_if_dependent(instruction,param_vars):
                                uaf_if = True
                            uaf = True
                            return uaf, uaf_if, double
            # Add following blocks only if current block have not initialized the variable
            if not initialized:
                for edge in current_block["block"].outgoing_edges:
                    if edge.target.start not in visited_blocks:
                        blocks.append({"block":edge.target,"start":edge.target.start,"end":edge.target.end})
        return uaf, uaf_if, double

    def get_xrefs_with_wrappers(self):
        free_xrefs = []
        for xref in self.get_xrefs_to_call(self.free_list):
            append = True
            if len(xref.params) > 0:
                param_vars = self.prepare_relevant_variables(xref.params[0])
                for var in param_vars["orig_vars"]:
                    if var in xref.function.source_function.parameter_vars:
                        wrapper_xrefs = self.get_xrefs_to_call([xref.function.source_function.name])
                        if wrapper_xrefs:
                            for wrapper_xref in wrapper_xrefs:
                                free_xrefs.append({
                                    "instruction": wrapper_xref,
                                    "param_index": list(xref.function.source_function.parameter_vars).index(var),
                                    "struct_free_wrapper": False
                                })
                        else:
                            # No xrefs -> struct free wrapper???
                            free_xrefs.append({
                                "instruction": xref,
                                "param_index": 0,
                                "struct_free_wrapper": True
                            })
                    elif append:
                        free_xrefs.append({
                            "instruction": xref,
                            "param_index": 0, # All the default free calls take just one parameter
                            "struct_free_wrapper": False
                        })
                        append = False
        return free_xrefs

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
                    tmp_possible.append(val)
                    vars["vars"].append(d.src.postfix_operands[0])
                    param_vars.append(d.src.postfix_operands[0])
                    for v in vars["vars"]:
                        val.replace(str(v),str(v)+"\\:?\\d*\\.?\\w*")
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
                    if re.search(param,str(parent)):
                        if_dep = False 
            parent = parent.parent
        return if_dep

    def get_xrefs_to_call(self,function_names):
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
            # Operator Delete refs -> TODO this takes long time -> REWORK for sure
            if symbol_name == "operator delete":
                if len(self.current_view.functions) < len(self.current_view.symbols):
                    symbol_list = self.current_view.functions
                    name = True
                else:
                    symbol_list = self.current_view.symbols
                    name = False
                for symbol in symbol_list:
                    if name:
                        sym = symbol.name
                    else:
                        sym = symbol
                    try:
                        if type(self.current_view.symbols[sym]) is list:
                            for item in self.current_view.symbols[sym]:
                                if "operator delete" in item.full_name and item not in symbol_item:
                                    symbol_item.append(item)
                        elif "operator delete" in self.current_view.symbols[sym].full_name and self.current_view.symbols[sym] not in symbol_item:
                            symbol_item.append(self.current_view.symbols[sym])
                    except:
                        pass
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
                                calls = extract_hlil_operations(instruction.function,[HighLevelILOperation.HLIL_CALL],specific_instruction=instruction)
                                for call in calls:
                                    if str(call.dest) in function_names and call not in xrefs:
                                        xrefs.append(call)
        return xrefs
