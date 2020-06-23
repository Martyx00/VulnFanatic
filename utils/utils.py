from binaryninja import *

def extract_hlil_operations(current_hlil,operations,instruction_address=-1,instruction_index=-1,specific_instruction=None):
    extracted_operations = []
    
    # Instruction index was specified, not need to stress just go through all levels of HLIL objects
    if instruction_index != -1:
        hlil_instructions = list(current_hlil.instructions)
        # If the instruction itself is what we are looking for
        if hlil_instructions[instruction_index].operation in operations:
                extracted_operations.append(hlil_instructions[instruction_index])
        # Go through all operands and extract all operations we are looking for
        operands_mag = []
        operands_mag.extend(hlil_instructions[instruction_index].operands)
        while operands_mag:
            op = operands_mag.pop()
            if type(op) == HighLevelILInstruction and op.operation in operations and op.instr_index == instruction_index:
                extracted_operations.append(op)
                operands_mag.extend(op.operands)
            elif type(op) == HighLevelILInstruction:
                operands_mag.extend(op.operands)
            elif type(op) is list:
                for o in op:
                    operands_mag.append(o)
    elif instruction_address != -1:
        hlil_instructions = list(current_hlil.instructions)
        # Looking for address
        # Build list with all addresses in function
        address_list = []
        for i in hlil_instructions:
            address_list.append(i.address)
        try:
            # First index of exactly matching address
            index = address_list.index(instruction_address)
            instruction = hlil_instructions[index]
            if instruction.operation in operations:
                extracted_operations.append(instruction)
            operands_mag = []
            operands_mag.extend(instruction.operands)
            # Since one address can appear multiple times in HLIL, we need to make sure that all lines are covered
            # if not at the end, look for more stuff with the same address
            multiple_with_same_address = False
            if index < len(hlil_instructions)-1:
                current_inst_address = instruction.address
                tmp_index = index+1
                tmp_inst = hlil_instructions[index+1]
                # Load operands from all lines with same address
                while tmp_inst.address == current_inst_address:
                    multiple_with_same_address = True
                    operands_mag.extend(tmp_inst.operands)
                    if hlil_instructions[tmp_index].operation in operations:
                        extracted_operations.append(hlil_instructions[tmp_index])
                    tmp_index += 1
                    tmp_inst = hlil_instructions[tmp_index]
            # With preloaded magazine, we can start searching
            while operands_mag:
                op = operands_mag.pop()
                if type(op) == HighLevelILInstruction and op.operation in operations and (op.instr_index == index or multiple_with_same_address):
                    extracted_operations.append(op)
                    operands_mag.extend(op.operands)
                elif type(op) == HighLevelILInstruction:
                    operands_mag.extend(op.operands)
                elif type(op) is list:
                    for o in op:
                        operands_mag.append(o)
        except ValueError:
            # Exactly matching address was not found
            log_warn("Address not found!")
    elif specific_instruction != None:
        # This is the simplest case
        if specific_instruction.operation in operations:
            extracted_operations.append(specific_instruction)
        operands_mag = []
        operands_mag.extend(specific_instruction.operands)
        while operands_mag:
            op = operands_mag.pop()
            if type(op) == HighLevelILInstruction and op.operation in operations:
                extracted_operations.append(op)
                operands_mag.extend(op.operands)
            elif type(op) == HighLevelILInstruction:
                operands_mag.extend(op.operands)
            elif type(op) is list:
                for o in op:
                    operands_mag.append(o)
    else:
        log_warn("Neither address, specific instruction nor index were provided!")
    return extracted_operations


def get_ssa_vars_read(current_hlil,current_hlil_ssa_instructions,instruction_index):
    vars_read = []
    try:
        source = current_hlil_ssa_instructions[instruction_index].src
        for operand in source if type(source) is list else [source]:
            if type(operand) == binaryninja.highlevelil.HighLevelILInstruction:
                vars_read.extend(extract_hlil_operations(current_hlil,[HighLevelILOperation.HLIL_VAR_SSA],specific_instruction=operand))
    except:
        pass
    return vars_read

def get_vars_read(current_hlil,current_hlil_instructions,instruction_index):
    # Problems with vars that are ADDRESS_OF
    vars_read = []
    for operand in current_hlil_instructions[instruction_index].src.operands:
        if type(operand) == binaryninja.highlevelil.HighLevelILInstruction:
            vars_read.extend(extract_hlil_operations(current_hlil,[HighLevelILOperation.HLIL_VAR],specific_instruction=operand))
    return vars_read

def get_hlil_ssa_phi_sources(current_hlil,phi_instruction):
    phi_sources = []
    for var in phi_instruction.src if type(phi_instruction.src) is list else [phi_instruction.src]:
        phi_sources.append(current_hlil.ssa_form.get_ssa_var_definition(var))
    return phi_sources


def get_constants_read_ssa(current_hlil,current_hlil_ssa_instructions,instruction_index):
    vars_read = []
    try:
        source = current_hlil_ssa_instructions[instruction_index].src
        for operand in source if type(source) is list else [source]:
            if type(operand) == binaryninja.highlevelil.HighLevelILInstruction:
                vars_read.extend(extract_hlil_operations(current_hlil.ssa_form,[HighLevelILOperation.HLIL_CONST_PTR,HighLevelILOperation.HLIL_CONST],specific_instruction=operand))
    except:
        pass
    return vars_read

def get_constants_read(current_hlil,current_hlil_instructions,instruction_index):
    vars_read = []
    for operand in current_hlil_instructions[instruction_index].src if type(current_hlil_instructions[instruction_index].src) is list else [current_hlil_instructions[instruction_index].src]:
        if type(operand) == binaryninja.highlevelil.HighLevelILInstruction:
            vars_read.extend(extract_hlil_operations(current_hlil,[HighLevelILOperation.HLIL_CONST_PTR,HighLevelILOperation.HLIL_CONST],specific_instruction=operand))
    return vars_read

def get_address_of_uses(current_hlil,current_hlil_instructions,addr_of_object):
    uses = []
    # Might require to return HLIL_VAR
    for index in range(addr_of_object.instr_index-1,0,-1):
        if str(addr_of_object) in str(current_hlil_instructions[index]):
            use = extract_hlil_operations(current_hlil,[HighLevelILOperation.HLIL_ADDRESS_OF],specific_instruction=current_hlil_instructions[index])
            for op in use:
                if str(addr_of_object) in str(op):
                    uses.append(op)
        # Return when we reach declaration
        if str(addr_of_object) in str(current_hlil_instructions[index]) and (current_hlil_instructions[index].operation == HighLevelILOperation.HLIL_VAR_INIT or current_hlil_instructions[index].operation == HighLevelILOperation.HLIL_VAR_DECLARE):
            # init or declaration was found, just break
            break
    return uses

# Returns single instruction which is either INIT or DECLARE
def get_address_of_init(current_hlil,current_hlil_instructions,addr_of_object):
    # Shortcut
    try:
        init_inst = current_hlil.get_var_definitions(addr_of_object.operands[0].var)[0]
        if init_inst.operation == HighLevelILOperation.HLIL_VAR_INIT:
            return init_inst
    except:
        pass
    for index in range(addr_of_object.instr_index-1,0,-1):
        # Return when we reach declaration
        if str(addr_of_object) in str(current_hlil_instructions[index]) and (current_hlil_instructions[index].operation == HighLevelILOperation.HLIL_VAR_INIT or current_hlil_instructions[index].operation == HighLevelILOperation.HLIL_VAR_DECLARE):
            # init or declaration was found, just break
            return current_hlil_instructions[index]


def get_xrefs_of_symbol(bv,symbol_name):
    xrefs = []
    xref_addr = []
    symbol_item = []
    try:
        symbol_item.extend(bv.symbols[symbol_name]) if type(bv.symbols[symbol_name]) is list else symbol_item.append(bv.symbols[symbol_name])
        #symbol_item = bv.symbols[symbol_name]
    except KeyError:
        pass
    try:
        symbol_item.extend(bv.symbols[symbol_name+"@IAT"]) if type(bv.symbols[symbol_name+"@IAT"]) is list else symbol_item.append(bv.symbols[symbol_name+"@IAT"])
    except KeyError:
        pass
    try:
        symbol_item.extend(bv.symbols[symbol_name+"@PLT"]) if type(bv.symbols[symbol_name+"@PLT"]) is list else symbol_item.append(bv.symbols[symbol_name+"@PLT"])
    except KeyError:
        pass
    
    for symbol in symbol_item if type(symbol_item) is list else [symbol_item]:
        if "sub_" in symbol_name:
            # Unnamed function is represented as address
            symbol_name = symbol_name.replace("sub_","0x")
        for ref in bv.get_code_refs(symbol.address):
            hlil_instructions = list(ref.function.hlil.instructions)
            for block in ref.function.hlil.basic_blocks:
                if symbol_name in str(hlil_instructions[block.start:block.end]):
                    for instruction in hlil_instructions[block.start:block.end]:
                        instr_string = str(instruction)
                        try:
                            str_op = str(instruction.dest)
                        except:
                            str_op = ""
                        xref_count = instr_string.count(symbol_name)
                        if symbol_name in instr_string:
                            if symbol_name == str_op and instruction.operation in [HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL] and not instruction.address in xref_addr:
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
                                if symbol_name == str_op and type(op) == HighLevelILInstruction and op.operation in [HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL] and not op.address in xref_addr:
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


def get_xrefs_of_addr(bv,address,symbol_name):
    xrefs = []
    xref_addr = []
    if "sub_" in symbol_name:
        # Unnamed function is represented as address
        symbol_name = symbol_name.replace("sub_","0x")
    try:
        for ref in bv.get_code_refs(address):
            hlil_instructions = list(ref.function.hlil.instructions)
            for block in ref.function.hlil.basic_blocks:
                if symbol_name in str(hlil_instructions[block.start:block.end]):
                    for instruction in hlil_instructions[block.start:block.end]:
                        instr_string = str(instruction)
                        try:
                            str_op = str(instruction.dest)
                        except:
                            str_op = ""
                        xref_count = instr_string.count(symbol_name)
                        if symbol_name in instr_string:
                            if symbol_name == str_op and instruction.operation in [HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL] and not instruction.address in xref_addr:
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
                                if symbol_name == str_op and type(op) == HighLevelILInstruction and op.operation in [HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL] and not op.address in xref_addr:
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
    except KeyError:
        pass
    return xrefs