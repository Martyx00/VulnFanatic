from binaryninja import *

class FunctionTracer:
    def __init__(self,current_view):
        self.current_view = current_view

    def selected_function_tracer(self,current_function,call_address):
        function_trace_struct = {
            "function":current_function,
            "call_address": hex(call_address),
            "sources":[]
            }
        call_instruction = None
        hlil_block = None
        basic_block_index = current_function.basic_blocks.index(current_function.get_basic_block_at(call_address))
        #if hlil_block:
        for instruction in list(current_function.hlil.instructions):
            if instruction.address == call_address:
                if instruction.operation == HighLevelILOperation.HLIL_CALL:
                    call_instruction = instruction
                else:
                    for operand in instruction.operands:
                        if type(operand) is list and len(operand) == 1:
                            # Single item list
                            if operand[0].operation == HighLevelILOperation.HLIL_CALL:
                                call_instruction = operand[0]
                        elif type(operand) == HighLevelILInstruction and operand.operation == HighLevelILOperation.HLIL_CALL and operand.address == call_address:
                            call_instruction = operand
                        elif type(operand) == HighLevelILInstruction:
                            # Function call can be veeery deep :(
                            operands_mag = []
                            operands_mag.extend(operand.operands)
                            while operands_mag:
                                op = operands_mag.pop()
                                if type(op) == HighLevelILInstruction and op.operation == HighLevelILOperation.HLIL_CALL:
                                    # We can get address of call instruction for highlighting and other purposes
                                    call_instruction = op
                                elif type(op) == HighLevelILInstruction:
                                    operands_mag.extend(op.operands)
                                #log_info(str(op))
                                
        # Call instruction should be well set now :)  
        if call_instruction:
            log_info(str(call_instruction.params))
            for param in call_instruction.params:
                if param.operation == HighLevelILOperation.HLIL_CONST_PTR:
                    # Cosnt ptr
                    try:
                        value = self.current_view.get_string_at(param.constant).value
                    except:
                        value = hex(param.constant)
                    function_trace_struct["sources"].append({
                        "param": call_instruction.params.index(param),
                        "function_calls": [],
                        "call_basic_block_start": call_instruction.il_basic_block.start,
                        "source_basic_block_start": None,
                        "same_branch": True,
                        "value": value,
                        "def_instruction_address": None,
                        "var_type": "constant_ptr",
                        "exported": False,
                        "var": None,
                        "function":current_function
                    })
                    continue
                    
                elif param.operation == HighLevelILOperation.HLIL_CONST:
                    # Const
                    function_trace_struct["sources"].append({
                        "param": call_instruction.params.index(param),
                        "function_calls": [],
                        "call_basic_block_start": call_instruction.il_basic_block.start,
                        "source_basic_block_start": None,
                        "same_branch": True,
                        "value": hex(param.constant),
                        "def_instruction_address": None,
                        "var_type": "constant",
                        "exported": False,
                        "var": None,
                        "function":current_function
                    })
                    continue
                # Not constant handlers below
                function_trace_struct["sources"].extend(self.trace_var(param,current_function,call_instruction.address))
                # Update param index
                for src in function_trace_struct["sources"]:
                    if src["param"] == None:
                        src["param"] = call_instruction.params.index(param)
        log_info(str(function_trace_struct))
        return function_trace_struct

    def trace_var(self,variable,current_function,call_address):
        # This should ideally work on top of HLIL 
        current_source = {
            "param": None,
            "function_calls": [],
            "call_basic_block_start": current_function.get_low_level_il_at(call_address).il_basic_block.start,
            "source_basic_block_start": None,
            "same_branch": True,
            "value": None,
            "def_instruction_address": None,
            "var_type": None,
            "exported": False,
            "var": variable,
            "function":current_function
        }
        sources = [current_source]
        anti_recurse_list = [str(variable)+"@"+current_function.name]
        source_index = 0
        param_sources = []
        vars_mag = [{
            "variable":variable,
            "current_call_address": call_address #This will be changed to XREFs wherever we will change function neccessary
        }]
        while vars_mag:
            mag_size = len(vars_mag)
            current_variable = vars_mag.pop(0)
            current_function = current_variable
            # we will work with non-ssa only and see what happens :)
            if mag_size > len(vars_mag):
                # TODO do magic
                # Found end of trace
                source_index += 1 
            # More branches
            elif mag_size < len(vars_mag):
                for i in range(mag_size,len(vars_mag)):
                    sources.append(current_source.copy())

        sources.extend(param_sources)
        return sources
            
        

    def get_var_function_calls(self):
        # This should get all function calls that the variable is part of, including places where it is assigned a return value!
        pass

    def get_xrefs_to(self,address):
        function_refs = [
                (ref.function,ref.address)
                for ref in self.current_view.get_code_refs(address)
            ]
        return function_refs
        