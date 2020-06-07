from binaryninja import *
from ..utils.utils import get_xrefs_of_symbol,extract_hlil_operations
# TODO double free completely
# TODO use il_basic_block dominators to see whether there is allocation that always occurs before a call to free (really applicable only in loops) - need to evaluate paths separately!
# TODO "operator delete"
'''
{
    "null_set": false,
    "struct_free_wrapper": true,
    "in_loop": true,
    "object_used_without_if_checks": true,
    "object_used": true,
    "called_multiple_times_without_inits": true,
    "always_allocated": false
}
'''


class FreeScanner:
    def __init__(self,current_view,xrefs_cache = dict()):
        self.current_view = current_view
        self.xrefs_cache = xrefs_cache
       
        self.free_list = ["free","_free","_freea","freea","free_dbg","_free_dbg","free_locale","_free_locale","operator delete"]        

    def trace_free(self):     
        result = []
        free_xrefs = []
        tmp_free_xrefs = self.get_free_calls(self.free_list)
        for xref in tmp_free_xrefs:
            free_xrefs.append({
                "instruction": xref,
                "param_index": 0 # All the default free calls take just one parameter
            })

        for free_xref in free_xrefs:
            append = True
            xref_index = free_xref["instruction"].instr_index
            current_hlil_instructions = list(free_xref["instruction"].function.instructions)
            current_free_xref_obj = {
                "name":free_xref["instruction"].function.source_function.name,
                "free_xref": free_xref["instruction"],
                "null_set": True,
                "struct_free_wrapper": False,
                "in_loop": False,
                "object_used_without_if_checks": False,
                "object_used": False,
                "called_multiple_times_without_inits": False,
                "always_allocated": False
            }
            in_loop = self.is_in_loop(free_xref["instruction"])
            param_var = self.extract_param_var(free_xref["instruction"],free_xref["param_index"])
            current_free_xref_obj["in_loop"] = in_loop["in_loop"]
            if param_var in free_xref["instruction"].function.source_function.parameter_vars:
                # Since this is wrapper, if XREFs to the wrapper are found shall we ignore it?
                # If only assign XREFS are found it needs to be recorded
                wrapper_xrefs = self.get_free_calls([free_xref["instruction"].function.source_function.name])
                for wrapper_xref in wrapper_xrefs:
                    # Is wrapper used in struct object
                    if wrapper_xref.operation == HighLevelILOperation.HLIL_ASSIGN:
                        current_free_xref_obj["struct_free_wrapper"] = True
                    else:
                        # Ignore this xref as we have a wrapper that is being called?
                        append = False
                        free_xrefs.append({
                            "instruction": wrapper_xref,
                            "param_index": list(free_xref["instruction"].function.source_function.parameter_vars).index(param_var) 
                        })
            instructions = []
            if free_xref["instruction"].operation != HighLevelILOperation.HLIL_TAILCALL:
                if in_loop["in_loop"]:
                    # Load instructions with all lines in body of the loop
                    for i in in_loop["loop"].body.lines:
                        instructions.append(i.il_instruction)
                    current_free_xref_obj["always_allocated"] = self.get_preallocations(current_free_xref_obj["free_xref"],param_var,current_hlil_instructions,in_loop["loop"].il_basic_block.start)
                    #current_free_xref_obj["always_allocated"] = False
                else:
                    # Not in loop so load instructions with all lines that follow the "free" call
                    instructions = current_hlil_instructions[xref_index+1:]
                for ins in instructions:
                    if ins:
                        if ins.instr_index == current_free_xref_obj["free_xref"].instr_index:
                            # Skip this as this is not relevant for us
                            continue
                        if str(param_var) in str(ins) and str(param_var)+"_" not in str(ins):
                            try:
                                dest = ins.dest
                            except:
                                dest = None
                            if dest != param_var and current_hlil_instructions[ins.instr_index].operation != HighLevelILOperation.HLIL_IF:
                                current_free_xref_obj["object_used"] = True
                                log_info(str(ins))
                                closest_if = self.find_closest_if(ins)
                                if closest_if != None and str(param_var) in str(closest_if):
                                    current_free_xref_obj["object_used_without_if_checks"] = False
                                else:
                                    current_free_xref_obj["object_used_without_if_checks"] = True
                
            if append:
                current_free_xref_obj["null_set"] = self.is_set_to_null(free_xref["instruction"],param_var,current_hlil_instructions)
                result.append(current_free_xref_obj.copy())
                self.evaluate_result(current_free_xref_obj)
        #log_info(str(result))
        #return result

    def evaluate_result(self,result):
        # Use after-free
        # !null_set && struct_free_wrapper => Low
        # !null_set && object_used_without_if_checks => High
        # !null_set && in_loop => Info
        # !null_set && object_used => Medium
        confidence = ""
        if not result["null_set"] and result["object_used_without_if_checks"] and not result["always_allocated"]:
            confidence = "High"
        elif not result["null_set"] and result["object_used"] and not result["always_allocated"]:
            confidence = "Medium"
        elif not result["null_set"] and result["struct_free_wrapper"] and not result["always_allocated"]:
            confidence = "Low"
        elif not result["null_set"] and result["in_loop"] and not result["always_allocated"]:
            confidence = "Info"
        if confidence:
            tag = result["free_xref"].function.source_function.create_tag(self.current_view.tag_types["[VulnFanatic] "+confidence], "Potential Use-afer-free Vulnerability", True)
            result["free_xref"].function.source_function.add_user_address_tag(result["free_xref"].address, tag)


    def get_preallocations(self,instruction,param_var,hlil_instructions,loop_boundary):
        root = {
            "block":instruction.il_basic_block,
            "start":instruction.il_basic_block.start,
            "end":instruction.instr_index,
            "alloc":False,
            "blocks_on_current_path":[instruction.il_basic_block.start],
            "dominators":[]
            }
        blocks = [root]
        while blocks:
            current_block = blocks.pop()
            for inst_index in range(current_block["start"],current_block["end"]):
                inst_string = str(hlil_instructions[inst_index])
                if "alloc" in inst_string and str(param_var) in inst_string:
                    current_block["alloc"] = True
            # Check incoming branches and populate blocks list if there are any
            if current_block["block"].incoming_edges and current_block["start"] != loop_boundary:
                for b in current_block["block"].incoming_edges:
                    if b.source.start not in current_block["blocks_on_current_path"]:
                        current_block["blocks_on_current_path"].append(b.source.start)
                        source = {
                            "block":b.source,
                            "start":b.source.start,
                            "end":b.source.end,
                            "alloc":current_block["alloc"],
                            "blocks_on_current_path":current_block["blocks_on_current_path"].copy(),
                            "dominators":[]
                            }
                        current_block["dominators"].append(source)
                        blocks.append(source)
            elif not current_block["alloc"]:
                # No incoming edges -> top of the trace -> if path without alloc was found we can happily return False as path without alloc exists
                return False
        log_info(str(root))
        return True

        for dominator in instruction.il_basic_block.strict_dominators:
            for inst_index in range(dominator.start,dominator.end):
                # Lame but works
                if "alloc" in str(hlil_instructions[inst_index]):
                    return True
        return False

    def extract_param_var(self,instruction,param_index):
        if instruction.params[param_index].operation == HighLevelILOperation.HLIL_VAR:
            return instruction.params[param_index].var
        else:
            tmp_array = []
            tmp_array.extend(instruction.params[param_index].operands.copy())
            while tmp_array:
                op = tmp_array.pop(0)
                if type(op) == HighLevelILInstruction:
                    if op.operation == HighLevelILOperation.HLIL_VAR:
                        return op.var
                    else:
                        for o in list(reversed(op.operands)):
                            tmp_array.insert(0,o)
        return None
                    


    def is_in_loop(self,instruction):
        loop_object = {"loop":None,"in_loop":False}
        parent = instruction.parent
        while parent != None:
            if parent.operation == HighLevelILOperation.HLIL_DO_WHILE or parent.operation == HighLevelILOperation.HLIL_FOR or parent.operation == HighLevelILOperation.HLIL_WHILE:
                loop_object = {"loop":parent,"in_loop":True}
                return loop_object
            parent = parent.parent
        return loop_object

    def find_closest_if(self,instruction):
        parent = instruction.parent
        while parent != None:
            if parent.operation == HighLevelILOperation.HLIL_IF:
                return parent
            parent = parent.parent
        return None

    def is_set_to_null(self,instruction,var,hlil_instructions):
        # Go through instructions in current block and see if there is any instruction setting 0 to something, if yes, check if the variable is related to the param passed to the free or its wrapper
        variables = [var]
        if var:
            for use in instruction.function.get_var_definitions(var):
                vars = extract_hlil_operations(instruction.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=hlil_instructions[use.instr_index])
                for v in vars:
                    if v not in variables:
                        variables.append(v)
        for variable in variables:
            for instruction_index in range(instruction.instr_index+1,instruction.il_basic_block.end):
                current_instruction = hlil_instructions[instruction_index]
                if current_instruction.operation == HighLevelILOperation.HLIL_ASSIGN and str(variable) in str(current_instruction.dest):
                    if (current_instruction.src.operation == HighLevelILOperation.HLIL_CONST or current_instruction.src.operation == HighLevelILOperation.HLIL_CONST_PTR) and current_instruction.src.constant == 0:
                        return True 
        return False

    # Slightly adjusted function form utils to reflect needs of this scanner
    def get_free_calls(self,free_functions):
        xrefs = []
        xref_addr = []
        symbol_item = []
        for symbol_name in free_functions:
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
            # Operator Delete refs:
            if symbol_name == "operator delete":
                for sym in self.current_view.symbols:
                    if type(self.current_view.symbols[sym]) is list:
                        for item in self.current_view.symbols[sym]:
                            if "operator delete" in item.full_name and item not in symbol_item:
                                symbol_item.append(item)
                    elif "operator delete" in self.current_view.symbols[sym].full_name and self.current_view.symbols[sym] not in symbol_item:
                        symbol_item.append(self.current_view.symbols[sym])
            for symbol in symbol_item if type(symbol_item) is list else [symbol_item]:
                for ref in self.current_view.get_code_refs(symbol.address):
                    hlil_instructions = list(ref.function.hlil.instructions)
                    for block in ref.function.hlil.basic_blocks:
                        if symbol_name in str(hlil_instructions[block.start:block.end]):
                            for instruction in hlil_instructions[block.start:block.end]:
                                instr_string = str(instruction)
                                try:
                                    str_op = str(instruction.dest)
                                except:
                                    str_op = ""
                                try:
                                    str_src = str(instruction.src)
                                except:
                                    str_src = ""
                                xref_count = instr_string.count(symbol_name)
                                if symbol_name in instr_string:
                                    if (symbol_name == str_op or symbol_name == str_src) and instruction.operation in [HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL,HighLevelILOperation.HLIL_ASSIGN] and not instruction.address in xref_addr and instruction.function.source_function.name not in self.free_list:
                                        xrefs.append(instruction)
                                        xref_addr.append(instruction.address)
                                        xref_count -= 1
                                    operands_mag = []
                                    operands_mag.extend(instruction.operands)
                                    while operands_mag:
                                        op = operands_mag.pop()
                                        try:
                                            str_op = str(op.dest)
                                        except:
                                            str_op = ""
                                        try:
                                            str_src = str(op.src)
                                        except:
                                            str_src = ""
                                        if (symbol_name == str_op or symbol_name == str_src) and type(op) == HighLevelILInstruction and op.operation in [HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL,HighLevelILOperation.HLIL_ASSIGN] and not op.address in xref_addr and op.function.source_function.name not in self.free_list:
                                            xrefs.append(op)
                                            xref_addr.append(op.address)
                                            operands_mag.extend(op.operands)
                                            xref_count -= 1
                                            if xref_count == 0:
                                                break
                                        elif type(op) == HighLevelILInstruction:
                                            operands_mag.extend(op.operands)
                                        elif type(op) is list:
                                            for o in op:
                                                operands_mag.append(o)
        return xrefs