from binaryninja import *
from ..utils.utils import extract_hlil_operations, get_constants_read, get_vars_read
# TODO xrefs
# TODO same branch
# TODO get_function_calls
# TODO address_of everywhere

class FunctionTracer:
    def __init__(self,current_view):
        self.current_view = current_view

    def selected_function_tracer(self,call_instruction,current_function):
        # TODO when param is function call!
        function_trace_struct = {
            "function":current_function,
            "call_address": hex(call_instruction.address),
            "sources":[]
            } 
         
        for param in call_instruction.params:
            if param.operation == HighLevelILOperation.HLIL_CONST_PTR:
                # Const ptr
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
                    "function_name":current_function.name,
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
                    "function_name":current_function.name,
                    "exported": False,
                    "var": None,
                    "function":current_function
                })
                continue
            # Not constant handlers below
            # First this needs to ensure that we work with HLIL_VARS and theoretically addresses only
            # TODO add HighLevelILOperation.HLIL_ADDRESS_OF
            param_vars = extract_hlil_operations(current_function.hlil,[HighLevelILOperation.HLIL_VAR],specific_instruction=param)
            for param_var in param_vars:
                function_trace_struct["sources"].extend(self.trace_var(param_var,call_instruction.il_basic_block.start))
            # Update param index
            for src in function_trace_struct["sources"]:
                if src["param"] == None:
                    src["param"] = call_instruction.params.index(param)
        log_info(str(function_trace_struct))
        return function_trace_struct

    def trace_var(self,variable,call_basic_block_start):
        # This should ideally work on top of HLIL only
        #log_info(str(current_function))
        sources = []
        #anti_recurse_list = [str(variable)+"@"+current_function.name]
        source_index = 0
        param_sources = []
        const_sources = []
        function_passes = []
        vars_mag = [{
            "variable":variable,
            "call_basic_block_start": call_basic_block_start, #This will be changed to XREFs wherever we will change function neccessary
            "function_calls": [],
            "current_call_index": variable.instr_index
        }]

        
        # HLIL_VAR_INIT with value vs HLIL_VAR_DECLARE without value
        # HLIL_ASSIGN assign value to already declared variable
        while vars_mag:
            mag_size = len(vars_mag)
            current_variable = vars_mag.pop()
            current_function = current_variable["variable"].function
            # Add to function call stack
            # TODO maybe used only for debugging
            if str(current_variable["variable"])+"@"+current_function.source_function.name not in function_passes:
                function_passes.append(str(current_variable["variable"])+"@"+current_function.source_function.name)
            else:
                continue
            
            
            # Get uses like fun calls etc...
            # TODO
            current_variable["function_calls"].extend(self.get_var_function_calls(current_variable,current_function))
            # get def instruction
            
            def_instructions = current_function.get_var_definitions(current_variable["variable"].var)
            if def_instructions:
                for def_instruction in def_instructions:
                    # Get all varaibles and constants at definition
                    if str(current_variable["variable"]) in str(def_instruction):
                        
                        def_instruction_variables = get_vars_read(current_function,def_instruction.instr_index)
                        if len(def_instruction_variables) == 0:
                            def_instruction_variables = get_constants_read(current_function,def_instruction.instr_index)
                        # Remove current variable
                        for def_var in def_instruction_variables:
                            if def_var.operation == HighLevelILOperation.HLIL_VAR:
                                # Ensure that there are no duplicates and that we are moving up in the function trace
                                if def_var.var != current_variable["variable"].var and def_var.instr_index < current_variable["variable"].instr_index:
                                    vars_mag.append({
                                        "variable":def_var,
                                        "call_basic_block_start": current_variable["call_basic_block_start"],
                                        "function_calls": current_variable["function_calls"].copy(),
                                        "current_call_index": current_variable["current_call_index"]
                                    })
                            # TODO adjust for address of later on :)
                            elif (def_var.operation == HighLevelILOperation.HLIL_CONST or def_var.operation == HighLevelILOperation.HLIL_CONST_PTR):
                                
                                value = hex(def_var.constant)
                                const_type = "constant"
                                # Const ptr
                                if def_var.operation == HighLevelILOperation.HLIL_CONST_PTR:
                                    const_type = "constant_ptr"
                                    try:
                                        value = self.current_view.get_string_at(def_var.constant).value
                                    except:
                                        value = hex(def_var.constant)
                                
                                const_sources.append({
                                    "param": None,
                                    "function_calls": current_variable["function_calls"],
                                    "call_basic_block_start": current_variable["call_basic_block_start"],
                                    "source_basic_block_start": def_instruction.il_basic_block.start,
                                    "same_branch": True,
                                    "value": value,
                                    "def_instruction_address": def_instruction.address,
                                    "var_type": const_type,
                                    "function_name":current_function.source_function.name,
                                    "exported": False,
                                    "var": current_variable["variable"].var,
                                    "function":current_function
                                })
            # Parameter          
            elif current_variable["variable"].var in current_function.source_function.parameter_vars:
                #log_info("PARAM: "+str(current_variable["variable"].var))
                # First check if function is exported
                exported = False
                for sym in self.current_view.get_symbols_of_type(SymbolType.FunctionSymbol):
                    if sym.binding == SymbolBinding.GlobalBinding and sym.name == current_function.source_function.name:
                        # Exported function
                        exported = True
                param_index = 0
                for arg in current_function.source_function.parameter_vars:
                    if arg == current_variable["variable"].var:
                        break
                    else:
                        param_index += 1
                # If exported add source
                if exported:
                    param_sources.append({
                        "param": None,
                        "function_calls": current_variable["function_calls"],
                        "call_basic_block_start": current_variable["call_basic_block_start"],
                        "source_basic_block_start": current_function.root, # TODO fix
                        "same_branch": True,
                        "value": None,
                        "def_instruction_address": None,
                        "var_type": "parameter:"+str(param_index),
                        "function_name":current_function.source_function.name,
                        "exported": exported,
                        "var": current_variable["variable"].var,
                        "function":current_function
                    })
                
                vars_mag.extend(self.get_xrefs_to(current_function,param_index,current_variable["function_calls"].copy()))
                    #log_info(str(operand))
                    # Add vars to vars_mag
            else:
                
                # No def instructions so somehow stack var???
                # Big TODO
                pass
            if mag_size > len(vars_mag):
                # found source
                # TODO hope this works :D
                function_passes = []
        sources.extend(param_sources)
        sources.extend(const_sources)
        return sources
            
        

    def get_var_function_calls(self,variable,current_function):
        # This should get all function calls that the variable is part of, including places where it is assigned a return value!
        # TODO have a look what the "lines" do
        # TODO add defitions and possible SSA vars to avoid missing stuff
        function_calls = []
        hlil_instructions = list(current_function.instructions)
        for use in current_function.get_var_uses(variable["variable"].var):
            line = hlil_instructions[use.instr_index]
            calls = extract_hlil_operations(current_function,[HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL],specific_instruction=line)
            for call in calls:
                if str(variable["variable"]) in str(call) and not any(x["call_address"] == call.address for x in function_calls) and call.instr_index < variable["current_call_index"]:
                    function_calls.append(
                        {
                            "instruction": call,
                            "call_address": call.address,
                            "call_index": call.instr_index,
                            "at_function": current_function.source_function.name,
                            "function_name": str(call.dest),
                            "function_call_basic_block_start": call.il_basic_block.start 
                        }
                    )
        return function_calls

    def get_xrefs_to(self,current_function,par_index,function_calls):
        xrefs_vars = []
        current_function_name = current_function.source_function.name
        function_refs = [
                (ref.function,ref.address)
                #for ref in self.current_view.get_code_refs(self.current_view.symbols["_strlen"][0].address)
                for ref in self.current_view.get_code_refs(current_function.source_function.lowest_address)
            ]
        for xref,addr in function_refs:

            # TODO try to get exact instruction index
            xref_hlil_instructions = list(xref.hlil.instructions)
            for instruction in xref_hlil_instructions:
                if current_function_name in str(instruction):
                    xref_calls = extract_hlil_operations(xref.hlil,[HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL],specific_instruction=instruction)
                    for xref_call in xref_calls:
                        if str(xref_call.dest) == current_function_name:
                            variables = extract_hlil_operations(xref.hlil,[HighLevelILOperation.HLIL_VAR],specific_instruction=xref_call.params[par_index])
                            for var in variables:
                                xrefs_vars.append({
                                    "variable":var,
                                    "call_basic_block_start": var.il_basic_block.start, 
                                    "function_calls": function_calls,
                                    "current_call_index": var.instr_index
                                })
        return xrefs_vars