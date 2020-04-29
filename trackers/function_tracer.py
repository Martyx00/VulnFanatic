from binaryninja import *
import time



class FunctionTracer:
    def __init__(self,bv,trace_ifs,scan_depth):
        self.bv = bv
        self.par_index = 0
        self.sources_comment = ""
        self.step_id = 0
        self.call_branch_dependence = []
        self.call_basic_block_start = -1
        self.trace_ifs = trace_ifs
        self.call_address = 0
        self.scan_depth = scan_depth

    def selected_function_tracer(self,function,call_addr):
        # Check if selection is function call
        master_object = {}
        if not function.get_low_level_il_at(call_addr):
            return None
        if function.get_low_level_il_at(call_addr).mlil:
            if function.get_low_level_il_at(call_addr).mlil.ssa_form.operation != MediumLevelILOperation.MLIL_CALL_SSA:
                return None
        #clicked_function_name = self.bv.get_function_at(function.get_low_level_il_at(call_addr).mlil.ssa_form.dest.operands[0]).name
        #master_object[clicked_function_name + "@" + function.name] = self.trace_function_call(function,call_addr)
        master_object = self.trace_function_call(function,call_addr)
        #log_info(str(master_object["sources"]))
        return master_object
        
    def trace_function_call(self,current_function,call_addr):
        # Function tracing structure
        self.call_address = call_addr
        function_trace_struct = {
            "function":current_function,
            "call_address": hex(call_addr),
            "params":{},
            "sources":[]
            }
        #  Get call instruction
        if "mips" in self.bv.arch.name:
            if current_function.get_low_level_il_at(call_addr).medium_level_il != None:
                call_instr = current_function.get_low_level_il_at(call_addr).medium_level_il.ssa_form
            # Mips calls have to be traced differently
            elif current_function.get_low_level_il_at(call_addr).ssa_form != None:
                if current_function.llil.get_ssa_reg_uses(current_function.get_low_level_il_at(call_addr).ssa_form.dest)[0].mlil != None:
                    call_instr = current_function.llil.get_ssa_reg_uses(current_function.get_low_level_il_at(call_addr).ssa_form.dest)[0].mlil.ssa_form
                    call_addr = call_instr.address
                    self.call_address = call_instr.address
                else:
                    return function_trace_struct
            else:
                return function_trace_struct
            
        elif current_function.get_low_level_il_at(call_addr).medium_level_il == None:
            return function_trace_struct
        else:
            call_instr = current_function.get_low_level_il_at(call_addr).medium_level_il.ssa_form
        
        if call_instr.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            #function_trace_struct["branch_dependence"].append(call_instr.branch_dependence)
            if call_instr.branch_dependence:
                self.call_branch_dependence.append(call_instr.branch_dependence)
            self.call_basic_block_start = call_instr.ssa_form.il_basic_block.start
            function_trace_struct["sources"] = []
            # Counter for parameter index
            self.par_index = 0
            if type(call_instr.params) is list:
                for param_vars in call_instr.params:
                    function_trace_struct["params"][self.par_index] = {}
                    if param_vars.value.is_constant:
                        if self.bv.get_string_at(param_vars.value.value):
                            # Constant is string
                            value = self.bv.get_string_at(param_vars.value.value).value
                        elif self.bv.get_symbol_at(param_vars.value.value):
                            # Constant is symbol
                            value = self.bv.get_symbol_at(param_vars.value.value).name
                        else:
                            # Neither string nor symbol
                            value = hex(param_vars.value.value)
                        function_trace_struct["sources"].extend([{
                                "value": value,
                                "if_dependencies": [],
                                "function_calls": [],
                                "var": None,
                                "def_instruction_address": None,
                                "var_type": "constant",
                                "exported": False,
                                "function": current_function,
                                "step_id": self.step_id,
                                "vars_read": {},
                                "param":self.par_index,
                                "branch_dependence": [],
                                "call_branch_dependence": []
                            }])
                        function_trace_struct["params"][self.par_index]["path"] = {}
                        if param_vars.value.type == RegisterValueType.ConstantPointerValue:
                            if self.bv.get_string_at(param_vars.value.value):
                                # Constant is string
                                value = self.bv.get_string_at(param_vars.value.value).value
                            elif self.bv.get_symbol_at(param_vars.value.value):
                                # Constant is symbol
                                value = self.bv.get_symbol_at(param_vars.value.value).name
                            else:
                                # Neither string nor symbol
                                value = hex(param_vars.value.value)
                            function_trace_struct["sources"].extend([{
                                "value": value,
                                "if_dependencies": [],
                                "function_calls": [],
                                "var": None,
                                "def_instruction_address": None,
                                "var_type": "constant_ptr",
                                "function": current_function,
                                "exported": False,
                                "step_id": self.step_id,
                                "vars_read": {},
                                "param":self.par_index,
                                "branch_dependence": [],
                                "call_branch_dependence": []
                            }])
                    for param in param_vars.vars_read:
                        # For each variable run a trace
                        var_path = self.trace_variable(current_function,param,self.trace_ifs,call_addr,False)
                        function_trace_struct["params"][self.par_index] = var_path["path"]
                        function_trace_struct["sources"].extend(var_path["sources"])
                    self.par_index += 1 
        return function_trace_struct

    def trace_variable(self,function,init_variable,trace_ifs,call_addr,current_function_only):
        start = time.time()
        var_path_struct = {}
        if_deps = []
        vars_mag = []
        #anti_recurse_var = []
        function_passes = []
        anti_recurse_list = []
        param_name = init_variable.var.name + "#" + str(init_variable.version)
        anti_recurse_list.append(param_name + "@" + function.name)
        self.step_id += 1
        var_path_struct = {
                "value": "",
                "if_dependencies": [],
                "function_calls": [],
                "var": init_variable,
                "def_instruction_address": None,
                "var_type": "",
                "exported": False,
                "step_id": self.step_id,
                "function":function,
                "function_name":function.name,
                "function_call_stack": [function.name],
                "call_address": call_addr,
                "vars_read": {},
                "call_branch_dependence": self.call_branch_dependence,
                "branch_dependence": []
            }
        sources = []
        sources_ifs = [[]]
        sources_func_calls = []
        vars_mag = [var_path_struct]
        function_passes.append([function.name])
        #anti_recurse_var.append({function.name:[]})
        
        branch_counter = 0
        basic_blocks = []
        sources_ifs[branch_counter] = []
        while vars_mag:
            if time.time() - start > 600:
                break
            self.step_id += 1
            mag_size = len(vars_mag)
            var_struct = vars_mag.pop()
            variable = var_struct["var"]
            var_struct["step_id"] = self.step_id
            try:
                var_name = variable.var.name + "#" + str(variable.version)
            except:
                var_name = variable.name
            if not var_struct["function_name"] in function_passes[branch_counter]:
                function_passes[branch_counter].append(var_struct["function_name"])
            
            if type(variable) == binaryninja.function.Variable:
                # Those are likely stack vars 
                # Need to check vars written as well and also need to avoid loops because of recursion
                # Get var definition
                def_instructions = var_struct["function"].mlil.ssa_form.get_var_definitions(variable)
                # Avoid ifs tracing
                if trace_ifs:
                    if_deps = self.get_ssa_var_if_deps(def_instructions,var_struct["function"])
                    sources_ifs[branch_counter].extend(if_deps)
                var_struct["if_dependencies"] = if_deps
                var_struct["function_calls"] = self.get_var_function_calls(variable,var_struct["function"])
                sources_func_calls.extend(var_struct["function_calls"].copy())
                if def_instructions:
                    for def_instruction in def_instructions:
                        if not def_instruction.ssa_form.il_basic_block in basic_blocks:
                            basic_blocks.append(def_instruction.ssa_form.il_basic_block)
                        if def_instruction.branch_dependence:
                            var_struct["branch_dependence"].append(def_instruction.branch_dependence)
                        var_struct["def_instruction_address"] = def_instruction.address
                        # If there are vars read that means it is an assignment of some kind ???
                        if def_instruction.vars_read:
                            for var_read in def_instruction.vars_read:
                                try:
                                    var_name = var_read.var.name + "#" + str(var_read.version)
                                except:
                                    var_name = var_read.name
                                anti_recurse_name = var_name + "@" + var_struct["function_name"]
                                if anti_recurse_name in anti_recurse_list:
                                    continue
                                else:
                                    anti_recurse_list.append(anti_recurse_name)
                                tmp_struct = {
                                    "value": "N/A",
                                    "if_dependencies": [],
                                    "function_calls": [],
                                    "var": var_read,
                                    "def_instruction_address": None,
                                    "var_type": "register_var",
                                    "exported": False,
                                    "step_id": self.step_id,
                                    "function": var_struct["function"],
                                    "function_name":var_struct["function"].name,
                                    "call_address": var_struct["call_address"],
                                    "function_call_stack": var_struct["function_call_stack"],
                                    "vars_read": {},
                                    "call_branch_dependence": var_struct["call_branch_dependence"],
                                    "branch_dependence":[]
                                }
                                if type(var_read) == binaryninja.function.Variable:
                                    var_struct["vars_read"][var_read.name] = tmp_struct 
                                else:
                                    var_struct["vars_read"][var_read.var.name + "#" + str(var_read.version)] = tmp_struct 
                                vars_mag.append(tmp_struct)
                else:
                    # NO def instruction so probably stack var
                    try:
                        stack_var_name = variable.var.name
                    except:
                        stack_var_name = variable.name
                    for i in var_struct["function"].medium_level_il.ssa_form.instructions:
                        # Stack variable
                        # set call_addr relevant to current function
                        if i.address >= var_struct["call_address"]:
                            continue
                        if stack_var_name in str(i.vars_read):
                            for var_written in i.vars_written:
                                try:
                                    var_name = var_written.var.name + "#" + str(var_written.version)
                                except:
                                    var_name = var_written.name
                                anti_recurse_name = var_name + "@" + var_struct["function_name"]
                                if anti_recurse_name in anti_recurse_list:
                                    continue
                                else:
                                    anti_recurse_list.append(anti_recurse_name)
                                tmp_struct = {
                                    "value": "N/A",
                                    "if_dependencies": [],
                                    "function_calls": [],
                                    "var": var_written,
                                    "def_instruction_address": None,
                                    "var_type": "stack_var",
                                    "exported": False,
                                    "step_id": self.step_id,
                                    "function": var_struct["function"],
                                    "function_name":var_struct["function"].name,
                                    "function_call_stack": var_struct["function_call_stack"],
                                    "call_address": var_struct["call_address"],
                                    "vars_read": {},
                                    "call_branch_dependence": var_struct["call_branch_dependence"],
                                    "branch_dependence":[]
                                }
                                if type(var_written) == binaryninja.function.Variable:
                                    var_struct["vars_read"][var_written.name] = tmp_struct 
                                else:
                                    var_struct["vars_read"][var_written.var.name + "#" + str(var_written.version)] = tmp_struct 
                                vars_mag.append(tmp_struct)
            else:
                # SSA var
                # Get var type
                var_type = "register_var"
                par_index = 0
                for param in var_struct["function"].parameter_vars:
                    if param == variable.var:
                        var_type = "parameter:" + str(par_index)
                        # for each XREF call trace_function_call
                        for sym in self.bv.get_symbols_of_type(SymbolType.FunctionSymbol):
                            if sym.binding == SymbolBinding.GlobalBinding and sym.name == var_struct["function"].name:
                                # Exported function
                                var_struct["exported"] = True
                        var_struct["var_type"] = var_type
                        tmp = var_struct.copy()
                        tmp.pop("vars_read")
                        tmp["param"] = self.par_index
                        s_ifs = sources_ifs[-1].copy()
                        tmp["if_dependencies"] = [i for n, i in enumerate(s_ifs) if i not in s_ifs[n + 1:]]
                        tmp["function_calls"] = sources_func_calls.copy()
                        sources.append(tmp)
                        # This limits the size of allowed function call stack
                        if not current_function_only and len(var_struct["function_call_stack"]) < self.scan_depth:
                            # Get initial XREFS
                            function_refs = [
                                    (ref.function,ref.address)
                                    for ref in self.bv.get_code_refs(var_struct["function"].lowest_address)
                                ]
                            # Recursively get all calls with the details
                            for xref,addr in function_refs:
                                if xref.name == var_struct["function_name"]:
                                    # if the function calls itself avoid infinite loops for recursive calls
                                    continue
                                # If the Xref is valid
                                if xref.get_low_level_il_at(addr):
                                    if xref.get_low_level_il_at(addr).operation == LowLevelILOperation.LLIL_CALL and not xref.name in function_passes[branch_counter]:
                                        # Found a function call
                                        if type(xref.get_low_level_il_at(addr).mlil.ssa_form.params) is list and par_index < len(xref.get_low_level_il_at(addr).mlil.ssa_form.params):
                                            for param_var in xref.get_low_level_il_at(addr).mlil.ssa_form.params[par_index].vars_read:
                                                fun_stack = var_struct["function_call_stack"].copy()
                                                call_branch = var_struct["call_branch_dependence"].copy()
                                                if xref.get_low_level_il_at(addr).mlil.ssa_form.branch_dependence:
                                                    call_branch.append(xref.get_low_level_il_at(addr).mlil.ssa_form.branch_dependence)
                                                fun_stack.append(xref.name)
                                                tmp_struct = {
                                                    "value": "N/A",
                                                    "if_dependencies": [],
                                                    "function_calls": [],
                                                    "var": param_var,
                                                    "def_instruction_address": None,
                                                    "var_type": "register_var",
                                                    "exported": False,
                                                    "step_id": self.step_id,
                                                    "function":xref,    
                                                    "function_name":xref.name,
                                                    "call_address":addr,
                                                    "function_call_stack": fun_stack.copy(),
                                                    "vars_read": {},
                                                    "call_branch_dependence": call_branch.copy(),
                                                    "branch_dependence": []
                                                }
                                                var_struct["vars_read"][param_var.var.name + "#" + str(param_var.version)] = tmp_struct
                                                #anti_recurse_var[branch_counter][xref.name].append(param_var.var.name + "#" + str(param_var.version))
                                                anti_recurse_list.append(param_var.var.name + "#" + str(param_var.version) + "@" + xref.name)
                                                vars_mag.append(tmp_struct)
                        break
                    par_index += 1
                # Get var definition
                def_instruction = var_struct["function"].mlil.ssa_form.get_ssa_var_definition(variable)
                
                # Avoid ifs tracing
                if trace_ifs:
                    if_deps = self.get_ssa_var_if_deps(def_instruction,var_struct["function"])
                    sources_ifs[branch_counter].extend(if_deps)
                var_struct["if_dependencies"] = if_deps
                var_struct["function_calls"] = self.get_ssa_var_function_calls(variable,var_struct["function"])
                sources_func_calls.extend(var_struct["function_calls"].copy())
                var_struct["var_type"] = var_type
                # There is a def instruction (we do not have arg/stack_var)
                if def_instruction:
                    if not def_instruction.ssa_form.il_basic_block in basic_blocks:
                        basic_blocks.append(def_instruction.ssa_form.il_basic_block)
                    if def_instruction.branch_dependence:
                        var_struct["branch_dependence"].append(def_instruction.branch_dependence)
                    var_struct["def_instruction_address"] = def_instruction.address
                    # There are vars_read so we do not have a constant
                    if def_instruction.vars_read:
                        for var_read in def_instruction.vars_read:
                            try:
                                var_name = var_read.var.name + "#" + str(var_read.version)
                            except:
                                var_name = var_read.name
                            anti_recurse_name = var_name + "@" + var_struct["function_name"]
                            if anti_recurse_name in anti_recurse_list:
                                continue
                            else:
                                anti_recurse_list.append(anti_recurse_name)
                            tmp_struct = {
                                "value": "N/A",
                                "if_dependencies": [],
                                "function_calls": [],
                                "var": var_read,
                                "def_instruction_address": None,
                                "var_type": "stack_var",
                                "exported": False,
                                "step_id": self.step_id,
                                "function":var_struct["function"],
                                "function_name":var_struct["function"].name,
                                "call_address": var_struct["call_address"],
                                "function_call_stack": var_struct["function_call_stack"],
                                "vars_read": {},
                                "call_branch_dependence": var_struct["call_branch_dependence"],
                                "branch_dependence": []
                            }
                            if type(var_read) == binaryninja.function.Variable:
                                var_struct["vars_read"][var_read.name] = tmp_struct 
                            else:
                                var_struct["vars_read"][var_read.var.name + "#" + str(var_read.version)] = tmp_struct 
                            vars_mag.append(tmp_struct)
                    elif def_instruction.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA and def_instruction.src.value.is_constant:
                        # Const pointer
                        if def_instruction.src.value.type == RegisterValueType.ConstantPointerValue:
                            var_struct["var_type"] = "constant_ptr"
                            if self.bv.get_string_at(def_instruction.src.value.value):
                                # Constant is string
                                value = self.bv.get_string_at(def_instruction.src.value.value).value
                            elif self.bv.get_symbol_at(def_instruction.src.value.value):
                                # Constant is symbol
                                value = self.bv.get_symbol_at(def_instruction.src.value.value).name
                            else:
                                # Neither string nor symbol
                                value = hex(def_instruction.src.value.value)
                            var_struct["value"] = value
                        # Int const
                        elif def_instruction.src.value.type == RegisterValueType.ConstantValue:
                            var_struct["var_type"] = "constant"
                            if self.bv.get_string_at(def_instruction.src.value.value):
                                # Constant is string
                                value = self.bv.get_string_at(def_instruction.src.value.value).value
                            elif self.bv.get_symbol_at(def_instruction.src.value.value):
                                # Constant is symbol
                                value = self.bv.get_symbol_at(def_instruction.src.value.value).name
                            else:
                                # Neither string nor symbol
                                value = hex(def_instruction.src.value.value)
                            var_struct["value"] = value
            
            if len(vars_mag) < mag_size:    
                # Since we reach end of trace, dump anti-recursion???
                #anti_recurse_var.pop()
                branch_counter -= 1
                function_passes.pop()
                tmp = var_struct.copy()
                s_ifs = sources_ifs.pop()
                tmp.pop("vars_read")
                tmp["param"] = self.par_index
                tmp["if_dependencies"] = [i for n, i in enumerate(s_ifs) if i not in s_ifs[n + 1:]]
                tmp["function_calls"] = sources_func_calls.copy()
                if tmp["def_instruction_address"]:
                    if tmp["function"].get_low_level_il_at(tmp["def_instruction_address"]).mlil:
                        instr = tmp["function"].get_low_level_il_at(tmp["def_instruction_address"]).mlil.ssa_form
                        if (instr.operation == MediumLevelILOperation.MLIL_CALL_SSA 
                        or instr.operation == MediumLevelILOperation.MLIL_TAILCALL_SSA 
                        or instr.operation == MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA 
                        or instr.operation == MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA):
                            if type(instr.dest.operands[0]) is int:
                                if self.bv.get_function_at(instr.dest.operands[0]):
                                    par_use_index = 0
                                    if type(instr.params) is list:
                                        par_count = len(instr.params)
                                        for par in instr.params:
                                            if variable.var.name in str(par):
                                                break
                                            par_use_index += 1
                                    else:
                                        par_count = 1

                                    # Get function that is called
                                    called_function = self.bv.get_function_at(instr.dest.operands[0])
                                    if instr.branch_dependence:
                                        br_dep = [instr.branch_dependence]
                                    else:
                                        br_dep = []
                                    same_block = False
                                    if instr.ssa_form.il_basic_block.start == self.call_basic_block_start:
                                        same_block = True
                                    tmp["function_calls"].append({
                                            "instruction": instr,
                                            "call_address": instr.address,
                                            "function_name": called_function.name,
                                            "param_index": par_use_index,
                                            "total_params": par_count,
                                            "branch_dependence": br_dep,
                                            "same_basic_block": same_block
                                        })
                        
                tmp["call_branch_dependence"] = self.call_branch_dependence.copy()
                tmp["basic_blocks"] = basic_blocks.copy()
                if not "parameter" in var_struct["var_type"]: 
                    sources.append(tmp)
                sources_func_calls = []
            if len(vars_mag) > mag_size:
                # There are multiple child nodes for the current variable
                # We will be branching
                #function_passes.append([])
                for br in range(0,len(vars_mag) - mag_size):
                    sources_ifs.append(sources_ifs[branch_counter].copy())
                    function_passes.append(function_passes[branch_counter].copy())
                    #anti_recurse_var.append(anti_recurse_var[branch_counter].copy())
                branch_counter += len(vars_mag) - mag_size
                
        return {"sources":sources,"path":{param_name:var_path_struct}}

    def get_var_function_calls(self,variable,function):
        calls_list = []
        vars_to_track = [variable]
        for use in function.mlil.ssa_form.get_var_uses(variable):
            if use.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                vars_written = use.vars_written
                for var_written in vars_written:
                    if var_written != variable and use.address < self.call_address:
                        vars_to_track.append(var_written.var)
        for var in vars_to_track:
            for use in function.mlil.ssa_form.get_var_uses(var):
                if not use.address == self.call_address:
                    if (use.operation == MediumLevelILOperation.MLIL_CALL_SSA 
                    or use.operation == MediumLevelILOperation.MLIL_TAILCALL_SSA
                    or use.operation == MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA
                    or use.operation == MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA
                    or use.operation == MediumLevelILOperation.MLIL_CALL
                    and use.address != self.call_address): 
                        if type(use.dest.operands[0]) is int:
                            if self.bv.get_function_at(use.dest.operands[0]):
                                # Found a call to function
                                # Get param index
                                par_use_index = 0
                                if type(use.params) is list:
                                    par_count = len(use.params)
                                    for par in use.params:
                                        if var.name in str(par):
                                            break
                                        par_use_index += 1
                                else:
                                    par_count = 1

                                if use.branch_dependence:
                                    br_dep = [use.branch_dependence]
                                else:
                                    br_dep = []
                                # Get function that is called
                                # This is very stupid but I have not found any other way
                                if type(use.dest.operands[0]) is int:
                                    called_function = self.bv.get_function_at(use.dest.operands[0])
                                    same_block = False
                                    if use.ssa_form.il_basic_block.start == self.call_basic_block_start:
                                        same_block = True
                                    calls_list.append({
                                            "instruction": use,
                                            "call_address": use.address,
                                            "function_name": called_function.name,
                                            "param_index": par_use_index,
                                            "total_params": par_count,
                                            "branch_dependence": br_dep,
                                            "same_basic_block": same_block
                                        })
                            else:
                                par_use_index = 0
                                if type(use.params) is list:
                                    par_count = len(use.params)
                                    for par in use.params:
                                        if var.name in str(par):
                                            break
                                        par_use_index += 1
                                else:
                                    par_count = 1

                                if use.branch_dependence:
                                    br_dep = [use.branch_dependence]
                                else:
                                    br_dep = []
                                same_block = False
                                if use.ssa_form.il_basic_block.start == self.call_basic_block_start:
                                    same_block = True
                                calls_list.append({
                                        "instruction": use,
                                        "call_address": use.address,
                                        "function_name": str(use.dest),
                                        "param_index": par_use_index,
                                        "total_params": par_count,
                                        "branch_dependence": br_dep,
                                        "same_basic_block": same_block
                                    })
        return calls_list
    
    def get_ssa_var_function_calls(self,variable,function):
        calls_list = []
        vars_to_track = [variable]
        for use in function.mlil.ssa_form.get_ssa_var_uses(variable):
            if use.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                vars_written = use.vars_written
                for var_written in vars_written:
                    if var_written != variable and use.address < self.call_address:
                        vars_to_track.append(var_written)
        for var in vars_to_track:
            for use in function.mlil.ssa_form.get_ssa_var_uses(var):
                if not use.address == self.call_address:
                    if (use.operation == MediumLevelILOperation.MLIL_CALL_SSA 
                    or use.operation == MediumLevelILOperation.MLIL_TAILCALL_SSA
                    or use.operation == MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA
                    or use.operation == MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA
                    or use.operation == MediumLevelILOperation.MLIL_CALL
                    and use.address != self.call_address): 
                        if type(use.dest.operands[0]) is int:
                            if self.bv.get_function_at(use.dest.operands[0]):
                                # Found a call to function
                                # Get param index
                                par_use_index = 0
                                if type(use.params) is list:
                                    par_count = len(use.params)
                                    for par in use.params:
                                        if var.var.name in str(par):
                                            break
                                        par_use_index += 1
                                else:
                                    par_count = 1

                                if use.branch_dependence:
                                    br_dep = [use.branch_dependence]
                                else:
                                    br_dep = []
                                # Get function that is called
                                # This is very stupid but I have not found any other way
                                if type(use.dest.operands[0]) is int:
                                    called_function = self.bv.get_function_at(use.dest.operands[0])
                                    same_block = False
                                    if use.ssa_form.il_basic_block.start == self.call_basic_block_start:
                                        same_block = True
                                    calls_list.append({
                                            "instruction": use,
                                            "call_address": use.address,
                                            "function_name": called_function.name,
                                            "param_index": par_use_index,
                                            "total_params": par_count,
                                            "branch_dependence": br_dep,
                                            "same_basic_block": same_block
                                        })
                            else:
                                par_use_index = 0
                                if type(use.params) is list:
                                    par_count = len(use.params)
                                    for par in use.params:
                                        if var.var.name in str(par):
                                            break
                                        par_use_index += 1
                                else:
                                    par_count = 1

                                if use.branch_dependence:
                                    br_dep = [use.branch_dependence]
                                else:
                                    br_dep = []
                                same_block = False
                                if use.ssa_form.il_basic_block.start == self.call_basic_block_start:
                                    same_block = True
                                calls_list.append({
                                        "instruction": use,
                                        "call_address": use.address,
                                        "function_name": str(use.dest),
                                        "param_index": par_use_index,
                                        "total_params": par_count,
                                        "branch_dependence": br_dep,
                                        "same_basic_block": same_block
                                    })
        return calls_list

    def get_ssa_var_if_deps(self,def_instruction,function):
        def_instructions = []
        if not def_instruction:
            return []
        if not type(def_instruction) is list:
            def_instructions.append(def_instruction)
        if_dependencies = []
        instructions = list(function.medium_level_il.ssa_form.instructions)
        # Count Ifs in function:
        if_count = 0
        for i in instructions:
            if i.operation == MediumLevelILOperation.MLIL_IF:
                if_count += 1
        for def_instruction in def_instructions:
            for if_dep in def_instruction.branch_dependence:
                if_params = []
                # Get all vars used in the if condition 
                try:
                    for left_var in instructions[if_dep].condition.left.vars_read:
                        if_params.append(left_var)
                    for right_var in instructions[if_dep].condition.right.vars_read:
                        if_params.append(right_var)
                except AttributeError:
                    pass
                # Trace origin of if variables
                origins = []
                if if_count < 10:
                    for if_param in if_params:
                        # For each param in if statement perform tracing and avoid tracing ifs for performance reasons
                        origins_path = self.trace_variable(function,if_param,False,instructions[if_dep].address,True)
                        for origin in origins_path["sources"]:
                            origin["var"] = if_param.var.name + "#" + str(if_param.version)
                        
                        origins.extend(origins_path["sources"])

                if_dependencies.append({
                    "var_origins": origins,
                    "condition": instructions[if_dep].condition,
                    "if_instruction_index": if_dep,
                    "if_instruction": instructions[if_dep],
                    "if_instruction_address": instructions[if_dep].address,
                    "branch": def_instruction.branch_dependence[if_dep]
                })
        return if_dependencies