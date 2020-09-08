from binaryninja import *
from .scanner.scanner3 import Scanner3
from .highlighter.highlighter3 import Highlighter3
from .utils.utils import extract_hlil_operations,get_xrefs_of_symbol
import os 
import sys


def scan3(bv):
	if not "[VulnFanatic] High" in bv.tag_types and not "[VulnFanatic] Medium" in bv.tag_types and not "[VulnFanatic] Low" in bv.tag_types and not "[VulnFanatic] Info" in bv.tag_types:
		bv.create_tag_type("[VulnFanatic] High","🔴")
		bv.create_tag_type("[VulnFanatic] Medium","🟠")
		bv.create_tag_type("[VulnFanatic] Low","🟡")
		bv.create_tag_type("[VulnFanatic] Info","🔵")
	scanner = Scanner3(bv)
	scanner.start()
	

def highlight3(bv,selection_addr):
	colors = ["Red","Blue","Cyan","Green","Magenta","Orange","Black","White","Yellow"]
	types = ["Assembly Blocks","HLIL Blocks","Assembly Variable","HLIL Variable"]
	try:
		current_function = bv.get_functions_containing(selection_addr)[0]
	except IndexError:
		show_message_box("Highlighter Error", "Not a valid highlight!", buttons=0, icon=2)
		return
	highlight_type = get_choice_input("Highlight Type","Select type of the highlighting",types)
	color_choice = get_choice_input("Highlight Color","Select color that will be used to highlight:",colors)
	if color_choice != None and highlight_type != None:
		high = Highlighter3(bv,selection_addr,current_function,colors[color_choice],types[highlight_type])
		high.start()

def clear_highlight3(bv,selection_addr):
	try:
		current_function = bv.get_functions_containing(selection_addr)[0]
	except IndexError:
		show_message_box("Highlighter Error", "Not a valid highlight!", buttons=0, icon=2)
		return
	high = Highlighter3(bv,selection_addr,current_function,None,"clear")
	high.start()

# Register the plugin
PluginCommand.register("VulnFanatic\\Start Scan", "Start Scan", scan3)
PluginCommand.register_for_address("VulnFanatic\\Highlight", "Highlights parameters with color highlights", highlight3)
PluginCommand.register_for_address("VulnFanatic\\Clear highlights", "Removes highlights of parameters", clear_highlight3)


#PluginCommand.register_for_address("TraceFanatic: Comment parameters", "Adds comments to variables that influence parameters of highlighted call", start_comment)
