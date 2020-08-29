from binaryninja import *
from ..utils.utils import extract_hlil_operations

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
        if "Assembly Blocks" in self.type:
            self.highlight_assembly_blocks()

    def highlight_assembly_blocks(self):
        visited_blocks = []
        blocks = []
        blocks.append(self.current_function.get_low_level_il_at(self.current_address).il_basic_block)
        while blocks:
            current_block = blocks.pop()
            visited_blocks.append(f"{current_block}@{current_block.function.name}")
            if current_block.start == 0 and "All functions" in self.type:
                blocks.extend(self.get_address_xref(current_block.function.start))
            current_block.highlight = self.color_set[self.color]
            for edge in current_block.incoming_edges:
                if f"{edge.source.start}@{edge.source.function.name}" not in visited_blocks:
                    blocks.append(edge.source)
                    visited_blocks.append(f"{edge.source.start}@{edge.source.function.name}")

    def get_address_xref(self,address):
        blocks = []
        refs = self.current_view.get_code_refs(address)
        for ref in refs:
            blocks.append(ref.function.get_low_level_il_at(ref.address).il_basic_block)
        return blocks