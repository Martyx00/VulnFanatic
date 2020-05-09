from binaryninja import *
from ..trackers.function_tracer2 import FunctionTracer

class Highlighter2(BackgroundTaskThread):
    def __init__(self,bv,call_instruction,current_function):
        BackgroundTaskThread.__init__(self, "[VulnFanatic] Testing tracing ... ", True)
        self.call_instruction = call_instruction
        self.bv = bv
        self.current_function = current_function

    def append_comment(self,addr,text):
        current_comment = self.bv.get_comment_at(addr)
        if text in current_comment:
            return
        if not "[VulnFanatic]" in current_comment:
            current_comment = "[VulnFanatic]\n" + text
            self.bv.set_comment_at(addr,current_comment)
            return
        self.bv.set_comment_at(addr,current_comment + "\n" + text)

    def run(self):
        fun_trace = FunctionTracer(self.bv)
        results = fun_trace.selected_function_tracer(self.call_instruction,self.current_function)
        self.progress = "[VulnFanatic] Completed tracing. Highlighting important points ..."
        for src in results["sources"]:
            # Highlight source if any
            if src["def_instruction_address"] != None:
                self.append_comment(src["def_instruction_address"],f"Source of parameter[{src['param']}]({src['param_var']})")
                src["function"].source_function.set_user_instr_highlight(src["def_instruction_address"],binaryninja.enums.HighlightStandardColor.RedHighlightColor)
            # Highlight function calls
            for fun_call in src["function_calls"]:
                self.append_comment(fun_call["call_address"],f"Affecting parameter[{src['param']}]({src['param_var']})")
                fun_call["at_function"].set_user_instr_highlight(fun_call["call_address"],binaryninja.enums.HighlightStandardColor.RedHighlightColor)



   