from binaryninja import *
from ..trackers.function_tracer import FunctionTracer

class Highlighter(BackgroundTaskThread):
    def __init__(self,bv,highlight,function,call_address,scan_depth):
        BackgroundTaskThread.__init__(self, "[VulnFanatic] Running the highlighter ... ", True)
        self.bv = bv
        self.high = highlight
        self.function = function
        self.call_addr = call_address
        self.scan_depth = scan_depth

    def run(self):
        if self.high:
            self.highlight(self.function,self.call_addr)
        else:
            self.clear_highlight(self.function,self.call_addr)


    def append_comment(self,addr,text):
        current_comment = self.bv.get_comment_at(addr)
        if text in current_comment:
            return
        if not "[VulnFanatic]" in current_comment:
            current_comment = "[VulnFanatic]\n" + text
            self.bv.set_comment_at(addr,current_comment)
            return
        self.bv.set_comment_at(addr,current_comment + "\n" + text)

    def highlight(self,function,call_address):
        # First highlight the marked function call
        function.set_user_instr_highlight(call_address,binaryninja.enums.HighlightStandardColor.RedHighlightColor)
        fun_tracer = FunctionTracer(self.bv,True,self.scan_depth)
        trace = fun_tracer.selected_function_tracer(function,call_address)
        self.progress = "[VulnFanatic] Completed tracing. Highlighting important points ..."
        for src in trace["sources"]:
            # Highlight/comment param source
            if src["def_instruction_address"]:
                src["function"].set_user_instr_highlight(src["def_instruction_address"],binaryninja.enums.HighlightStandardColor.RedHighlightColor)
                self.append_comment(src["def_instruction_address"],f"Source of param[{src['param']}]")
            elif "param" in src["var_type"]:
                if "[VulnFanatic]" not in src["function"].comment:
                    src["function"].comment = "[VulnFanatic]\n"
                if "Sources" not in src["function"].comment:
                    src["function"].comment += " - Sources:\n"
                if f"{src['function'].parameter_vars[int(src['var_type'].split(':')[1])]} source of param[{src['param']}]" not in src["function"].comment:
                    src["function"].comment += f"   - {src['function'].parameter_vars[int(src['var_type'].split(':')[1])]} source of param[{src['param']}]\n"
            # Highlight/comment function calls
            for fun_call in src["function_calls"]:
                self.append_comment(fun_call["call_address"],f"Affecting param[{src['param']}]")
                src["function"].set_user_instr_highlight(fun_call["call_address"],binaryninja.enums.HighlightStandardColor.RedHighlightColor)
            # Highlight/comment ifs
            for if_dep in src["if_dependencies"]:
                # Highlight the if instruction
                src["function"].set_user_instr_highlight(if_dep["if_instruction_address"],binaryninja.enums.HighlightStandardColor.RedHighlightColor)
                for origin in if_dep["var_origins"]:
                    for fun_call in origin["function_calls"]:
                        self.append_comment(fun_call["call_address"],f"Affecting IF instruction at {hex(if_dep['if_instruction_address'])}")
                        # Highlight function calls that affect the if instruction variables
                        src["function"].set_user_instr_highlight(fun_call["call_address"],binaryninja.enums.HighlightStandardColor.RedHighlightColor)
        # Append XREFS comments
        for src in trace["sources"]:
            function_refs = [(ref.function,ref.address) for ref in self.bv.get_code_refs(src["function"].lowest_address)]
            if function_refs:
                if "[VulnFanatic]" not in src["function"].comment:
                    src["function"].comment = "[VulnFanatic]\n"
                if "XREFS" not in src["function"].comment:
                    src["function"].comment += f" - XREFS:\n"
                if src["exported"] and "Exported" not in src["function"].comment:
                    src["function"].comment = src["function"].comment.replace("XREFS","XREFS (Exported)")
                for xref,addr in function_refs:
                    if f"{xref.name}@{hex(addr)}" not in src["function"].comment:
                        src["function"].comment += f"   - {xref.name}@{hex(addr)}\n"
        self.progress = ""

        
                
        
    def clear_highlight(self,function,call_address):
        # First highlight the marked function call
        function.set_user_instr_highlight(call_address,binaryninja.enums.HighlightStandardColor.NoHighlightColor)
        fun_tracer = FunctionTracer(self.bv,True,self.scan_depth)
        trace = fun_tracer.selected_function_tracer(function,call_address)
        self.progress = "[VulnFanatic] Completed tracing. Clearing auto highlights on important points ..."
        for src in trace["sources"]:
            src["function"].comment = ""
            # Highlight/comment param source
            if src["def_instruction_address"]:
                src["function"].set_user_instr_highlight(src["def_instruction_address"],binaryninja.enums.HighlightStandardColor.NoHighlightColor)
                self.bv.set_comment_at(src["def_instruction_address"],"")
            elif "param" in src["var_type"]:
                src["function"].comment = ""
            # Highlight/comment function calls
            for fun_call in src["function_calls"]:
                self.bv.set_comment_at(fun_call["call_address"],"")
                src["function"].set_user_instr_highlight(fun_call["call_address"],binaryninja.enums.HighlightStandardColor.NoHighlightColor)
            # Highlight/comment ifs
            for if_dep in src["if_dependencies"]:
                # Highlight the if instruction
                src["function"].set_user_instr_highlight(if_dep["if_instruction_address"],binaryninja.enums.HighlightStandardColor.NoHighlightColor)
                for origin in if_dep["var_origins"]:
                    for fun_call in origin["function_calls"]:
                        # Highlight function calls that affect the if instruction variables
                        self.bv.set_comment_at(fun_call["call_address"],"")
                        src["function"].set_user_instr_highlight(fun_call["call_address"],binaryninja.enums.HighlightStandardColor.NoHighlightColor)
        self.progress = ""
        