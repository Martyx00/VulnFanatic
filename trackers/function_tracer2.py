from binaryninja import *
from ..utils.utils import extract_hlil_operations, get_constants_read, get_address_of_uses, get_address_of_init, get_hlil_ssa_phi_sources, get_vars_read, get_ssa_vars_read,get_constants_read_ssa
import time
# TODO xrefs
# TODO same branch - Should be done, just validate
# TODO address_of vars read
# TODO MIPS seems to be fucked up
# TODO REALLY EVERYTHING needs to work with ssa_form otherwise the tracing is fucked up
# TODO check that memcpy in in libnetwork for sources (if any of them are relevant) -> turn on tracking of unexported params

class FunctionTracer:
    def __init__(self,current_view):
        self.current_view = current_view

    def selected_function_tracer(self,call_instruction,current_function):
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
            # First this needs to ensure that we work with HLIL_VARS
            param_vars = extract_hlil_operations(current_function.hlil,[HighLevelILOperation.HLIL_VAR],specific_instruction=param)
            param_calls = extract_hlil_operations(current_function.hlil,[HighLevelILOperation.HLIL_CALL],specific_instruction=param)
            for param_var in param_vars:
                function_trace_struct["sources"].extend(self.trace_var(param_var,call_instruction.il_basic_block.start))
            
            # Update param index
            for src in function_trace_struct["sources"]:
                if src["param"] == None:
                    src["param"] = call_instruction.params.index(param)
                    for call in param_calls:
                        src["function_calls"].append({
                            "instruction": call,
                            "call_address": call.address,
                            "call_index": call.instr_index,
                            "at_function": call.function.source_function.name,
                            "function_name": str(call.dest),
                            "same_branch": True,
                            "function_call_basic_block_start": call.il_basic_block.start 
                        })
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
        stack_var_sources = []
        function_passes = []
        previous_function = variable.function
        current_hlil_instructions = list(variable.function.instructions)
        current_hlil_ssa_instructions = list(variable.function.ssa_form.instructions)
        vars_mag = [{
            "variable":variable,
            "call_basic_block_start": call_basic_block_start, #This will be changed to XREFs wherever we will change function neccessary
            "function_calls": [],
            "current_call_index": variable.instr_index,
            "same_branch": True,
            "call_boundary": variable.instr_index,
            "function_passes": []
        }]

        
        # HLIL_VAR_INIT with value vs HLIL_VAR_DECLARE without value
        # HLIL_ASSIGN assign value to already declared variable
        while vars_mag:
            mag_size = len(vars_mag)
            current_variable = vars_mag.pop()
            current_function = current_variable["variable"].function
            if current_function != previous_function:
                previous_function = current_function
                current_hlil_instructions = list(current_function.instructions)
                current_hlil_ssa_instructions = list(current_function.ssa_form.instructions)

            # Add to function call stack
            # TODO maybe used only for debugging
            log_info("Tracing VAR: " + str(variable) + " ... " + str(current_variable["variable"]) + " type: " + str(type(current_variable["variable"])))
            if str(current_variable["variable"]) + hex(current_variable["variable"].address)+"@"+current_function.source_function.name in current_variable["function_passes"]:
                log_info("PASSED WITH:")
                log_info(str(current_variable["variable"]) + hex(current_variable["variable"].address)+"@"+current_function.source_function.name)
                continue
            else:
                current_variable["function_passes"].append(str(current_variable["variable"]) + hex(current_variable["variable"].address)+"@"+current_function.source_function.name)
            
            if current_variable["variable"].il_basic_block.start != current_variable["call_basic_block_start"] and current_variable["same_branch"]:
                current_variable["same_branch"] = False
            
            # Get uses like fun calls etc...
            current_variable["function_calls"] = current_variable["function_calls"] + [x for x in self.get_var_function_calls(current_variable,current_function,current_hlil_instructions,current_hlil_ssa_instructions) if x not in current_variable["function_calls"]]
            # Stack var
            if current_variable["variable"].parent.operation == HighLevelILOperation.HLIL_ADDRESS_OF:
                init_instr = get_address_of_init(current_function,current_hlil_instructions,current_variable["variable"])
                if init_instr.operation == HighLevelILOperation.HLIL_VAR_INIT:
                    vars_read = get_vars_read(current_function,current_hlil_instructions,init_instr.instr_index)
                    if len(vars_read) != 0:
                        for var_read in vars_read:
                            if var_read.operation == HighLevelILOperation.HLIL_VAR:
                                # Ensure that there are no duplicates and that we are moving up in the function trace
                                if var_read.var != current_variable["variable"].var and var_read.instr_index < current_variable["current_call_index"]:
                                    vars_mag.append({
                                        "variable":var_read,
                                        "call_basic_block_start": current_variable["call_basic_block_start"],
                                        "function_calls": current_variable["function_calls"].copy(),
                                        "current_call_index": current_variable["current_call_index"],
                                        "same_branch": current_variable["same_branch"],
                                        "call_boundary": var_read.instr_index,
                                        "function_passes": current_variable["function_passes"].copy()
                                    })
                else:
                    stack_var_sources.append({
                        "param": None,
                        "function_calls": current_variable["function_calls"],
                        "call_basic_block_start": current_variable["call_basic_block_start"],
                        "source_basic_block_start": init_instr.il_basic_block.start,
                        "same_branch": current_variable["same_branch"],
                        "value": None,
                        "def_instruction_address": init_instr.address, 
                        "var_type": "stack_variable",
                        "function_name":current_function.source_function.name,
                        "exported": False,
                        "var": current_variable["variable"].var,
                        "function":current_function
                    })
                continue
            
            # get def instruction
            def_instruction = current_function.ssa_form.get_ssa_var_definition(current_variable["variable"].ssa_form.var)
            if def_instruction:
                #for def_instruction in def_instructions:
                # Get all varaibles and constants at definition
                #if str(current_variable["variable"]) in str(def_instruction):
                def_instruction_variables = []
                if def_instruction.operation == HighLevelILOperation.HLIL_VAR_PHI:
                    phis = get_hlil_ssa_phi_sources(current_function,def_instruction)
                    for phi in phis:
                        if phi != None:
                            ssa_vars = get_ssa_vars_read(current_function,current_hlil_ssa_instructions,phi.ssa_form.instr_index)
                            for ssa_var in ssa_vars:
                                def_instruction_variables.append(ssa_var.non_ssa_form)
                            def_instruction_variables.extend(get_constants_read_ssa(current_function,current_hlil_ssa_instructions,phi.instr_index))
                    # HLIL var PHI
                elif def_instruction.operation != HighLevelILOperation.HLIL_VAR_DECLARE:
                    # TODO fix exception AttributeError: 'HighLevelILInstruction' object has no attribute 'src'
                    def_instruction_variables = get_ssa_vars_read(current_function,current_hlil_ssa_instructions,def_instruction.instr_index)
                if len(def_instruction_variables) == 0 and def_instruction.operation != HighLevelILOperation.HLIL_VAR_DECLARE:
                    def_instruction_variables = get_constants_read_ssa(current_function,current_hlil_ssa_instructions,def_instruction.instr_index)
                # Remove current variable
                for def_var in def_instruction_variables:
                    if def_var.operation == HighLevelILOperation.HLIL_VAR_SSA or def_var.operation == HighLevelILOperation.HLIL_VAR:
                        # Ensure that there are no duplicates and that we are moving up in the function trace
                        if def_var.var != current_variable["variable"].var and def_var.instr_index < current_variable["current_call_index"]:
                            vars_mag.append({
                                "variable":def_var.non_ssa_form,
                                "call_basic_block_start": current_variable["call_basic_block_start"],
                                "function_calls": current_variable["function_calls"].copy(),
                                "current_call_index": current_variable["current_call_index"],
                                "same_branch": current_variable["same_branch"],
                                "call_boundary": def_var.instr_index,
                                "function_passes": current_variable["function_passes"].copy()
                            })
                    elif ((def_var.operation == HighLevelILOperation.HLIL_CONST or def_var.operation == HighLevelILOperation.HLIL_CONST_PTR)) and def_var.parent.operation != HighLevelILOperation.HLIL_CALL:
                        # Constants but not not function calls 
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
                            "same_branch": def_instruction.il_basic_block.start == current_variable["call_basic_block_start"],
                            "value": value,
                            "def_instruction_address": def_instruction.address,
                            "var_type": const_type,
                            "function_name":current_function.source_function.name,
                            "exported": False,
                            "var": current_variable["variable"].var,
                            "function":current_function
                        })
                    elif def_var.parent.operation == HighLevelILOperation.HLIL_CALL:
                        #log_info(str(def_var.parent.operation))
                        #log_info(str(current_variable))
                        # Only function calls without parameters
                        stack_var_sources.append({
                            "param": None,
                            "function_calls": current_variable["function_calls"],
                            "call_basic_block_start": current_variable["call_basic_block_start"],
                            "source_basic_block_start": def_var.il_basic_block.start,
                            "same_branch": current_variable["same_branch"],
                            "value": None,
                            "def_instruction_address": def_var.address, 
                            "var_type": "stack_variable",
                            "function_name":current_function.source_function.name,
                            "exported": False,
                            "var": current_variable["variable"].var,
                            "function":current_function
                        })

            # Parameter          
            else:
                if type(current_variable["variable"]) == binaryninja.Variable:
                    var = current_variable["variable"]
                elif current_variable["variable"].operation == HighLevelILOperation.HLIL_VAR:
                    var = current_variable["variable"].var
                else:
                    var = current_variable["variable"].var.varc
                if var in current_function.source_function.parameter_vars:
                    # First check if function is exported
                    exported = False
                    for sym in self.current_view.get_symbols_of_type(SymbolType.FunctionSymbol):
                        if sym.binding == SymbolBinding.GlobalBinding and sym.name == current_function.source_function.name:
                            # Exported function
                            exported = True
                    '''param_index = 0
                    for arg in current_function.source_function.parameter_vars:
                        if arg == var:
                            break
                        else:
                            param_index += 1'''
                    param_index = list(current_function.source_function.parameter_vars).index(var)
                    # If exported add source
                    if exported:
                        param_sources.append({
                            "param": None,
                            "function_calls": current_variable["function_calls"],
                            "call_basic_block_start": current_variable["call_basic_block_start"],
                            "source_basic_block_start": current_function.root,
                            "same_branch": current_variable["same_branch"],
                            "value": None,
                            "def_instruction_address": None,
                            "var_type": "parameter:"+str(param_index),
                            "function_name":current_function.source_function.name,
                            "exported": exported,
                            "var": var,
                            "function":current_function
                        })
                    
                    vars_mag.extend(self.get_xrefs_to(current_function,param_index,current_variable))
                    #log_info(str(operand))
                    # Add vars to vars_mag

            if mag_size > len(vars_mag):
                # found source
                #function_passes = []
                pass
        sources.extend(param_sources)
        sources.extend(const_sources)
        sources.extend(stack_var_sources)
        return sources
            
        

    def get_var_function_calls(self,variable,current_function,current_hlil_instructions,current_hlil_ssa_instructions):
        # This should get all function calls that the variable is part of, including places where it is assigned a return value!
        #log_info(str(variable))
        function_calls = []
        variable_appearances = []
        hlil_instructions = list(current_function.instructions)
        if variable["variable"].parent.operation == HighLevelILOperation.HLIL_ADDRESS_OF:
            variable_appearances.extend(get_address_of_uses(current_function,current_hlil_instructions,variable["variable"].parent))
            #log_i nfo(str(variable_appearances))
        elif variable["variable"].operation == HighLevelILOperation.HLIL_VAR or variable["variable"].operation == HighLevelILOperation.HLIL_VAR_SSA:
            #log_info(str(variable))
            variable_appearances = current_function.get_ssa_var_uses(variable["variable"].ssa_form.var)
            def_inst = current_function.get_ssa_var_definition(variable["variable"].ssa_form.var)
            if def_inst:
                variable_appearances.append(def_inst)
        else:
            variable_appearances = current_function.get_ssa_var_uses(variable["variable"])
        for use in variable_appearances:
            line = hlil_instructions[use.instr_index]
            calls = extract_hlil_operations(current_function,[HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL],specific_instruction=line)
            for call in calls:
                if ((str(variable["variable"]) in str(call) and not any(x["call_address"] == call.address for x in function_calls) and call.instr_index < variable["current_call_index"] and call.instr_index < variable["call_boundary"])
                    or (("=" in str(use) and str(variable["variable"]) in str(use).split("=")[0]) and not any(x["call_address"] == call.address for x in function_calls) and call.instr_index < variable["current_call_index"] and call.instr_index < variable["call_boundary"])):
                    same_branch = False
                    if call.il_basic_block.start == variable["call_basic_block_start"]:
                        same_branch = True
                    function_calls.append(
                        {
                            "instruction": call,
                            "call_address": call.address,
                            "call_index": call.instr_index,
                            "at_function": current_function.source_function.name,
                            "function_name": str(call.dest),
                            "same_branch": same_branch and variable["same_branch"],
                            "function_call_basic_block_start": call.il_basic_block.start 
                        }
                    )
        return function_calls

    def get_xrefs_to(self,current_function,par_index,current_var):
        start_time = time.time()
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
                                    "function_calls": current_var["function_calls"].copy(),
                                    "current_call_index": var.instr_index,
                                    "same_branch": current_var["same_branch"],
                                    "call_boundary": var.instr_index,
                                    "function_passes": current_var["function_passes"].copy()
                                })
        log_info(f"Got {len(xrefs_vars)} XREFS in {time.time() - start_time}")
        return xrefs_vars

