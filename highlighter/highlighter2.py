from binaryninja import *
from ..trackers.function_tracer2 import FunctionTracer

class Highlighter2(BackgroundTaskThread):
    def __init__(self,bv,call_instruction,current_function):
        BackgroundTaskThread.__init__(self, "[VulnFanatic] Testing tracing ... ", True)
        self.call_instruction = call_instruction
        self.bv = bv
        self.current_function = current_function

    def run(self):
        fun_trace = FunctionTracer(self.bv)
        fun_trace.selected_function_tracer(self.call_instruction,self.current_function)


   