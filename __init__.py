from binaryninja import *
from .scanner.scanner2 import Scanner2
from .scanner.scanner3 import Scanner3
from .scanner.free_scanner2 import FreeScanner2
from .highlighter.highlighter2 import Highlighter2
from .utils.utils import extract_hlil_operations,get_xrefs_of_symbol
import os 
import sys
import time


def scan3(bv,selection_addr):
	if not "[VulnFanatic] High" in bv.tag_types and not "[VulnFanatic] Medium" in bv.tag_types and not "[VulnFanatic] Low" in bv.tag_types and not "[VulnFanatic] Info" in bv.tag_types:
		bv.create_tag_type("[VulnFanatic] High","🔴")
		bv.create_tag_type("[VulnFanatic] Medium","🟠")
		bv.create_tag_type("[VulnFanatic] Low","🟡")
		bv.create_tag_type("[VulnFanatic] Info","🔵")
	scanner = Scanner3(bv)
	scanner.start()


def scan2(bv,selection_addr):
	# Add tags
	if not "[VulnFanatic] High" in bv.tag_types and not "[VulnFanatic] Medium" in bv.tag_types and not "[VulnFanatic] Low" in bv.tag_types and not "[VulnFanatic] Info" in bv.tag_types:
		bv.create_tag_type("[VulnFanatic] High","🔴")
		bv.create_tag_type("[VulnFanatic] Medium","🟠")
		bv.create_tag_type("[VulnFanatic] Low","🟡")
		bv.create_tag_type("[VulnFanatic] Info","🔵")
	rules_path = os.path.dirname(os.path.realpath(__file__)) + "/scanner/rules.json"
	if rules_path:
		uaf = show_message_box("Use-after-free Scanner", "Would you like to also run the Use-after-free scanner?\n\n(Note that until the plugin reaches version 3.0 this feature is EXPERIMENTAL ONLY.)", buttons=1, icon=1)
		scanner = Scanner2(rules_path,bv,uaf)
		scanner.start()
	else:
		show_message_box("Scanner Error", "File with scan rules was not found!", buttons=0, icon=2)
		pass

def highlight2(bv,selection_addr):
	try:
		current_function = bv.get_functions_containing(selection_addr)[0]
	except IndexError:
		show_message_box("Highlighter Error", "Not a valid highlight!", buttons=0, icon=2)
		return
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
	high = Highlighter2(bv,call_instruction,current_function,True)
	high.start()
	

def clear_highlight2(bv,selection_addr):
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
	high = Highlighter2(bv,call_instruction,current_function,False)
	high.start()


# Register the plugin
PluginCommand.register_for_address("[VulnFanatic] Start Scan", "Start Scan", scan2)
PluginCommand.register_for_address("[VulnFanatic] TEST SCAN3", "TEST SCAN 3", scan3)
PluginCommand.register_for_address("[VulnFanatic] Highlight parameters", "Highlights parameters with color highlights", highlight2)
PluginCommand.register_for_address("[VulnFanatic] Clear highlighted parameters", "Removes highlights of parameters", clear_highlight2)


#PluginCommand.register_for_address("TraceFanatic: Comment parameters", "Adds comments to variables that influence parameters of highlighted call", start_comment)
