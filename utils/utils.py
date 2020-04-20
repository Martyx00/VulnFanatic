from binaryninja import *

def extract_hlil_operations(current_hlil,operations,instruction_address=-1,instruction_index=-1,specific_instruction=None):
    extracted_operations = []
    hlil_instructions = list(current_hlil.instructions)
    # Instruction index was specified, not need to stress just go through all levels of HLIL objects
    if instruction_index != -1:
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