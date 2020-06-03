from binaryninja import *
from ..utils.utils import get_xrefs_of_symbol,extract_hlil_operations
# Loops (+ _SSA):
#   HighLevelILOperation.HLIL_DO_WHILE
#   HighLevelILOperation.HLIL_FOR
#   HighLevelILOperation.HLIL_WHILE

# Info to collect:
#   branch dependence -> especially if conditions that use param of free
#   setting the pointer to NULL after a call to free (both inside free wrappers and couple instructions below their XREFS) -> can be tracked by simple True/False param

# Double free can be recognized by an If check on the free param before the free is called (outside loop with not check probably Info only)
# Use-after-free can be reported as info for cases where the pointer of the freed object is not set to NULL after being freed, low confidence when in loop, Info everywhere else
#   Make sure to handle this:
#000b0286              rdi_6 = var_858:8.q
#000b028d          if (rdi_6 != 0)
#000b0292              _free(rdi_6)
#                      var_858:8.q = 0
'''
{
    "null_set": false,
    "struct_free_wrapper": true,
    "in_loop": true,
    "object_used_without_if_checks": true,
    "object_used": true,
    "called_multiple_times_without_inits": true
}
'''
# Use after-free
# !null_set && struct_free_wrapper => Low
# !null_set && object_used_without_if_checks => High
# !null_set && in_loop => Info
# !null_set && object_used => Medium

# Double-free
# called_multiple_times_without_inits => Medium

# ALGO DRAFT:
# Get xref to free call
# if source of the free param is parmeter to current function -> probably a free wrapper:
#   add xrefs to current_function to tracing pipeline (relevant to given param)
#   if xrefs only HLIL_ASSIGN operations:
#       use of free wrapper in struct -> mark as Info if free not followed by setting the pointer to NULL (struct_free_wrapper: True ???)
# if free (or xref to function that calls free and passes value from parameter to it) is in the loop and not followed by break:
#   trace the usage of the parameter to free both up and down within boundaries of the loop
# else:
#   not in loop, trace down until end of function


class FreeScanner:
    def __init__(self,current_view,xrefs_cache = dict()):
        self.current_view = current_view
        self.xrefs_cache = xrefs_cache
        # TODO "operator delete"
        self.free_list = ["free","_free","_freea","freea","free_dbg","_free_dbg","free_locale","_free_locale","operator delete"]        

    def trace_free(self):
        # TODO the null_set part
        # Get all XREFs to free calls
        # For each XREF:
        #   if in loop:
        #       set "in_loop" = true
        #   if it is a free wrapper:
        #       append all calls to XREF list (must include INIT type of XREFs)
        #       if param to free not set to null after:
        #           null_set = false
        #       if init xref only:
        #           set "struct_free_wrapper" = true
        #   if param to this xref not set to null after:
        #       null_set = false
        #   get all uses of the param to this xref in current function
        #   for all uses:
        #       if "in_loop":
        #           account for all uses within the loop when setting object_used_without_if_checks and object_used
        #       else:
        #           account only uses after the free when setting object_used_without_if_checks and object_used
        #       
        result = []
        free_xrefs = []
        tmp_free_xrefs = self.get_free_calls(self.free_list)
        for xref in tmp_free_xrefs:
            free_xrefs.append({
                "instruction": xref,
                "param_index": 0 # All the default free calls take just one parameter
            })

        # TODO need to keep track of param index for wrappers
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
                "called_multiple_times_without_inits": False
            }
            in_loop = self.is_in_loop(free_xref["instruction"])
            # Not working
            #param_var = free_xref["instruction"].params[free_xref["param_index"]].var
            # new version
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
                        # TODO Need to somehow pass the information on the "null_set" part???
                        append = False
                        free_xrefs.append({
                            "instruction": wrapper_xref,
                            "param_index": list(free_xref["instruction"].function.source_function.parameter_vars).index(param_var) 
                        })
            instructions = []
            if in_loop["in_loop"]:
                # Load instructions with all lines in body of the loop
                for i in in_loop["loop"].body.lines:
                    instructions.append(i.il_instruction)
            else:
                # Not in loop so load instructions with all lines that follow the "free" call
                instructions = current_hlil_instructions[xref_index+1:]
            for ins in instructions:
                if ins:
                    if ins.instr_index == current_free_xref_obj["free_xref"].instr_index:
                        # Skip this as this is not relevant for us
                        continue
                    if str(param_var) in str(ins):
                        try:
                            dest = ins.dest
                        except:
                            dest = None
                        if dest != param_var and current_hlil_instructions[ins.instr_index].operation != HighLevelILOperation.HLIL_IF:
                            current_free_xref_obj["object_used"] = True
                            closest_if = self.find_closest_if(ins)
                            if closest_if != None and str(param_var) in str(closest_if):
                                current_free_xref_obj["object_used_without_if_checks"] = False
                            else:
                                current_free_xref_obj["object_used_without_if_checks"] = True
            
            if append:
                current_free_xref_obj["null_set"] = self.is_set_to_null(free_xref["instruction"],param_var,current_hlil_instructions)
                result.append(current_free_xref_obj.copy())
        log_info(str(result))
        return result

    def extract_param_var(self,instruction,param_index):
        if instruction.params[param_index].operation == HighLevelILOperation.HLIL_VAR:
            return instruction.params[param_index].var
        else:
            tmp_array = []
            tmp_array.extend(instruction.params[param_index].operands.copy())
            while tmp_array:
                log_info(str(tmp_array))
                op = tmp_array.pop(0)
                if type(op) == HighLevelILInstruction:
                    if op.operation == HighLevelILOperation.HLIL_VAR:
                        return op.var
                    else:
                        for o in list(reversed(op.operands)):
                            tmp_array.insert(0,o)
            log_info(str(tmp_array))
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
        # TODO make sure to check for the note in beginign ofthis file
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