from binaryninja import *
from .scanner.scanner import Scanner
from .scanner.scanner2 import Scanner2
from .highlighter.highlighter import Highlighter
from .highlighter.highlighter2 import Highlighter2
from .trackers.function_tracer2 import FunctionTracer
from .utils.utils import extract_hlil_operations,get_xrefs_of_symbol
import os 
import sys
import time


def scan2(bv,selection_addr):
	# Add tags
	if not "[VulnFanatic] High" in bv.tag_types and not "[VulnFanatic] Medium" in bv.tag_types and not "[VulnFanatic] Low" in bv.tag_types and not "[VulnFanatic] Info" in bv.tag_types:
		bv.create_tag_type("[VulnFanatic] High","🔴")
		bv.create_tag_type("[VulnFanatic] Medium","🟠")
		bv.create_tag_type("[VulnFanatic] Low","🟡")
		bv.create_tag_type("[VulnFanatic] Info","🔵")
	rules_path = os.path.dirname(os.path.realpath(__file__)) + "/scanner/rules.json"
	if rules_path:
		scanner = Scanner2(rules_path,bv)
		scanner.start()

def highlight2(bv,selection_addr):
	start_time = time.time()	
	current_function = bv.get_functions_containing(selection_addr)[0]
	function_calls_at_address = []
	function_calls_at_address = extract_hlil_operations(current_function.hlil,[HighLevelILOperation.HLIL_CALL],instruction_address=selection_addr)
	if len(function_calls_at_address) == 0:
		show_message_box("Highlighter Error", "Highlighted instruction is not a function call!", buttons=0, icon=2)
		return
	elif len(function_calls_at_address) == 1:
		call_instruction = function_calls_at_address[0]
	else:
		choice = get_choice_input("Functions","Select function call",[str(i)+"@"+hex(i.address)+"  " for i in function_calls_at_address])
		call_instruction = function_calls_at_address[choice]
	high = Highlighter2(bv,call_instruction,current_function)
	high.start()
	log_info("WHOLE JOB TIME: " + str(time.time() - start_time))

def clear_highlight2(bv,selection_addr):
	pass

def test(bv,selection_addr):
	# With this it takes roughly 0.5 second to trace one XREF
	start_time = time.time()	
	current_function = bv.get_functions_containing(selection_addr)[0]
	function_calls_at_address = []
	function_calls_at_address = extract_hlil_operations(current_function.hlil,[HighLevelILOperation.HLIL_CALL],instruction_address=selection_addr)
	if len(function_calls_at_address) == 0:
		show_message_box("Highlighter Error", "Highlighted instruction is not a function call!", buttons=0, icon=2)
		return
	elif len(function_calls_at_address) == 1:
		call_instruction = function_calls_at_address[0]
	else:
		choice = get_choice_input("Functions","Select function call",[str(i)+"@"+hex(i.address)+"  " for i in function_calls_at_address])
		call_instruction = function_calls_at_address[choice]
	fun_trace = FunctionTracer(bv)
	fun_trace.selected_function_tracer(call_instruction,current_function)
	log_info(str(time.time() - start_time))

def highlight(bv,selection_addr):
	current_function = bv.get_functions_containing(selection_addr)[0]
	if current_function.get_low_level_il_at(selection_addr).mlil == None or current_function.get_low_level_il_at(selection_addr).mlil.ssa_form.operation != MediumLevelILOperation.MLIL_CALL_SSA:
		show_message_box("Highlighter Error", "Highlighted instruction is not a function call!", buttons=0, icon=2)
		return
	highlighter = Highlighter(bv,True,current_function,selection_addr,1000)
	highlighter.start()

def clear_highlight(bv,selection_addr):
	current_function = bv.get_functions_containing(selection_addr)[0]
	if current_function.get_low_level_il_at(selection_addr).operation != LowLevelILOperation.LLIL_CALL:
		show_message_box("Highlighter Error", "Highlighted instruction is not a function call!", buttons=0, icon=2)
		return
	highlighter = Highlighter(bv,False,current_function,selection_addr,1000)
	highlighter.start()

def scan(bv,selection_addr):
	# Create tag types
	try:
		depth_limit = int(get_text_line_input("Set number of functions that will be followed during the scan (set to 0 for unlimited).", "Specify scan depth"))
		if depth_limit < 0:
			show_message_box("Scanner Error", "Specified scan depth not valid!", buttons=0, icon=2)
			return
		if depth_limit == 0:
			depth_limit = sys.maxsize * 2 + 1
	except:
		show_message_box("Scanner Error", "Specified scan depth not valid!", buttons=0, icon=2)
		return
	if not "[VulnFanatic] High" in bv.tag_types and not "[VulnFanatic] Medium" in bv.tag_types and not "[VulnFanatic] Low" in bv.tag_types and not "[VulnFanatic] Info" in bv.tag_types:
		bv.create_tag_type("[VulnFanatic] High","🔴")
		bv.create_tag_type("[VulnFanatic] Medium","🟠")
		bv.create_tag_type("[VulnFanatic] Low","🟡")
		bv.create_tag_type("[VulnFanatic] Info","🔵")
	#rules_path = get_open_filename_input("Choose file with scanning rules ...")
	rules_path = os.path.dirname(os.path.realpath(__file__)) + "/scanner/rules.json"
	if rules_path:
		scanner = Scanner(rules_path,bv,depth_limit + 1)
		scanner.start()

# Register the plugin
PluginCommand.register_for_address("[VulnFanatic] Highlight parameters", "Highlights parameters with color highlights", highlight)
PluginCommand.register_for_address("[VulnFanatic] Clear highlighted parameters", "Removes highlights of parameters", clear_highlight)
PluginCommand.register_for_address("[VulnFanatic] Start Scan", "Start Scan", scan)
PluginCommand.register_for_address("[VulnFanatic] Start Scan 2", "Start Scan2", scan2)
PluginCommand.register_for_address("[VulnFanatic] Highlight parameters2", "Highlights parameters with color highlights", highlight2)
PluginCommand.register_for_address("[VulnFanatic] Clear highlighted parameters2", "Removes highlights of parameters", clear_highlight2)
PluginCommand.register_for_address("[VulnFanatic] Test", "Test", test)


#PluginCommand.register_for_address("TraceFanatic: Comment parameters", "Adds comments to variables that influence parameters of highlighted call", start_comment)
