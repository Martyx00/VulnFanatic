from binaryninja import *
from ..utils.utils import extract_hlil_operations
import re

class Highlighter3(BackgroundTaskThread):
    def __init__(self,bv,current_address,current_function,color,type):
        self.progress_banner = f"[VulnFanatic] Running the highlight of {type}"
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.current_view = bv
        self.current_address = current_address
        self.current_function = current_function
        self.color = color
        self.type = type
        self.color_set = {
            "Black": binaryninja.highlight.HighlightStandardColor.BlackHighlightColor,
            "Blue": binaryninja.highlight.HighlightStandardColor.BlueHighlightColor,
            "Cyan": binaryninja.highlight.HighlightStandardColor.CyanHighlightColor,
            "Green": binaryninja.highlight.HighlightStandardColor.GreenHighlightColor,
            "Magenta": binaryninja.highlight.HighlightStandardColor.MagentaHighlightColor,
            "Orange": binaryninja.highlight.HighlightStandardColor.OrangeHighlightColor,
            "Red": binaryninja.highlight.HighlightStandardColor.RedHighlightColor,
            "White": binaryninja.highlight.HighlightStandardColor.WhiteHighlightColor,
            "Yellow": binaryninja.highlight.HighlightStandardColor.YellowHighlightColor
        }

    def run(self):
        if self.type == "Assembly Blocks":
            self.highlight_assembly_blocks()
        elif self.type == "HLIL Variable":
            self.highlight_hlil_var()
        elif self.type == "HLIL Blocks":
            self.highlight_hlil_blocks()
        elif self.type == "Assembly Variable":
            self.highlight_assembly_variable()
        elif self.type == "clear":
            self.clear()

    def clear(self):
        for instruction in self.current_function.hlil.instructions:
            self.current_function.set_auto_instr_highlight(instruction.address,binaryninja.highlight.HighlightStandardColor.NoHighlightColor)
        for instruction in self.current_function.mlil.instructions:
            self.current_function.set_auto_instr_highlight(instruction.address,binaryninja.highlight.HighlightStandardColor.NoHighlightColor)
        for b in self.current_function.basic_blocks:
            b.set_auto_highlight(binaryninja.highlight.HighlightStandardColor.NoHighlightColor) 
        for b in self.current_function.hlil.basic_blocks:
            b.set_auto_highlight(binaryninja.highlight.HighlightStandardColor.NoHighlightColor) 

    def highlight_assembly_blocks(self):
        visited_blocks = []
        blocks = []
        blocks.append(self.current_function.get_low_level_il_at(self.current_address).il_basic_block)
        while blocks:
            current_block = blocks.pop()
            visited_blocks.append(f"{current_block}@{current_block.function.name}")
            current_block.set_auto_highlight(self.color_set[self.color]) 
            for edge in current_block.incoming_edges:
                if f"{edge.source.start}@{edge.source.function.name}" not in visited_blocks:
                    blocks.append(edge.source)
                    visited_blocks.append(f"{edge.source.start}@{edge.source.function.name}")

    def highlight_hlil_blocks(self):
        visited_blocks = []
        blocks = []
        current_hlil = self.current_function.hlil
        current_hlil_instructions = list(current_hlil.instructions)
        for ins in current_hlil_instructions:
            if ins.address == self.current_address:
                blocks.append(ins.il_basic_block)
        while blocks:
            current_block = blocks.pop()
            visited_blocks.append(f"{current_block}@{current_block.function.name}")
            current_block.set_auto_highlight(self.color_set[self.color]) 
            for edge in current_block.incoming_edges:
                if f"{edge.source.start}@{edge.source.function.name}" not in visited_blocks:
                    blocks.append(edge.source)
                    visited_blocks.append(f"{edge.source.start}@{edge.source.function.name}")

    def highlight_assembly_variable(self):
        vars_to_trace = []
        vars_choice = []
        checked_vars = []
        tmp_mlil = self.current_function.get_low_level_il_at(self.current_address).mlil
        disass_text = self.current_function.get_basic_block_at(self.current_address).disassembly_text
        for dt in disass_text:
            if dt.address == self.current_address:
                ins = dt
                break
        if tmp_mlil:
            vars_choice.extend(tmp_mlil.vars_read)
            vars_choice.extend(tmp_mlil.vars_written)
            var_choice = get_choice_input(f"Available variables for instruction:\n {hex(self.current_address)} {str(ins)}","Choose variable",vars_choice)
            vars_to_trace.append(vars_choice[var_choice])
            checked_vars.append(vars_choice[var_choice].name)
        while vars_to_trace:
            current_var = vars_to_trace.pop()
            for instruction in self.current_function.mlil.instructions:
                if instruction.address == self.current_address:
                    continue
                if current_var in instruction.vars_read:
                    # A varaible we are looking for was read from
                    # Highlight this place
                    self.current_function.set_auto_instr_highlight(instruction.address,self.color_set[self.color])
                elif current_var in instruction.vars_written:
                    self.current_function.set_auto_instr_highlight(instruction.address,self.color_set[self.color])
    
    def highlight_hlil_var(self):
        trace_vars = []
        current_hlil = self.current_function.hlil
        current_hlil_instructions = list(current_hlil.instructions)
        for ins in current_hlil_instructions:
            if ins.address == self.current_address and ins.operation != HighLevelILOperation.HLIL_LABEL:
                variables = extract_hlil_operations(current_hlil,[HighLevelILOperation.HLIL_VAR],specific_instruction=ins)
                calls = extract_hlil_operations(current_hlil,[HighLevelILOperation.HLIL_CALL,HighLevelILOperation.HLIL_TAILCALL],specific_instruction=ins)
                for call in calls:
                    try:
                        variables = set(variables.extend(call.params))
                    except:
                        pass
                variables = list(set(variables))
                var_choice = get_choice_input(f"Available variables for instruction:\n {hex(self.current_address)} {str(ins)}","Choose variable",variables)
                if var_choice != None:
                    trace_vars = self.prepare_relevant_variables(variables[var_choice])
                    self.current_function.set_auto_instr_highlight(self.current_address,self.color_set[self.color])
                    #break
        for instruction in current_hlil_instructions:
            for var in trace_vars["possible_values"]:
                # Remove when fixed
                try:
                    if re.search(var,str(instruction)):
                        self.current_function.set_auto_instr_highlight(instruction.address,self.color_set[self.color])
                except re.error:
                    pass

    def prepare_relevant_variables(self,param):
        vars = {
            "possible_values": [],
            "vars": [],
            "orig_vars": {}
        }
        param_vars_hlil = extract_hlil_operations(param.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=param)
        param_vars = []
        original_value = str(param)
        for p in param_vars_hlil:
            vars["orig_vars"][str(p)] = []
            param_vars.append(p.var)
        for param_var in vars["orig_vars"]:
            # For each of the original variables find its possible alternatives
            for var in param_vars:
                if var not in vars["orig_vars"][param_var]:
                    vars["orig_vars"][param_var].append(var)
                    vars["vars"].append(var)
                definitions = param.function.get_var_definitions(var)
                # Also uses are relevant
                definitions.extend(param.function.get_var_uses(var))
                for d in definitions:
                    if (d.operation == HighLevelILOperation.HLIL_VAR_INIT or d.operation == HighLevelILOperation.HLIL_ASSIGN) and re.search(str(var), str(d.src)):
                        # assign and variable we are tracing is in src
                        for v in extract_hlil_operations(param.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=d.dest):
                            # do appending
                            if v.var not in vars["orig_vars"][param_var]:
                                vars["orig_vars"][param_var].append(v.var)
                                param_vars.append(v.var)
                    elif (d.operation == HighLevelILOperation.HLIL_VAR_INIT or d.operation == HighLevelILOperation.HLIL_ASSIGN) and re.search(str(var), str(d.dest)):
                        # Variable currently tracing is in dest
                        for v in extract_hlil_operations(param.function,[HighLevelILOperation.HLIL_VAR],specific_instruction=d.src):
                            # do appending
                            if v.var not in vars["orig_vars"][param_var]:
                                vars["orig_vars"][param_var].append(v.var)
                                param_vars.append(v.var)
            for v in vars["orig_vars"][param_var]:
                tmp = re.escape(re.sub(f'{param_var}\.\w+|:\d+\.\w+', str(v), original_value))
                tmp2 = tmp.replace(str(v), str(v)+"((:\\d+\\.\\w+)?\\b|\\.\\w+\\b)?")
                if tmp2 not in vars["possible_values"]:
                    vars["possible_values"].append(tmp2)
        return vars