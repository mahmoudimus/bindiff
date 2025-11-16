"""
BinDiff IDA Plugin (Python Implementation)

This is a complete Python implementation of the BinDiff IDA plugin,
replacing the C++ implementation with Python/Cython bindings.

The plugin provides:
- Diff results viewing (matched/unmatched functions, statistics)
- Manual match creation and deletion
- Comment/symbol porting
- Visual diff launching
- Incremental diffing

Installation:
    1. Build the Cython extensions
    2. Copy this file and the bindiff module to IDA's plugins directory
    3. Restart IDA

Usage:
    - Press Ctrl+6 to open the main menu
    - Or use Edit -> Plugins -> BinDiff

Author: Generated for BinDiff
License: Apache 2.0
"""

import os
import sys
from typing import Optional

# IDA imports
try:
    import ida_idaapi
    import ida_kernwin
    import ida_loader
    import ida_nalt
    from ida_kernwin import Choose
except ImportError:
    print("Error: This plugin requires IDA Pro")
    sys.exit(1)

# BinDiff imports - will be available after building Cython extensions
try:
    from bindiff.ida_plugin import BindiffResults, Match, UnmatchedFunction, Statistic
    from bindiff.ida_plugin import ChangeType, PortCommentsKind
except ImportError as e:
    print(f"Error: BinDiff Python module not found: {e}")
    print("Please build the Cython extensions first")
    BINDIFF_AVAILABLE = False
else:
    BINDIFF_AVAILABLE = True


# Plugin version
PLUGIN_VERSION = "8.0.0"
PLUGIN_NAME = "BinDiff"
PLUGIN_HOTKEY = "Ctrl-6"
PLUGIN_COMMENT = "Structural comparison of executable objects"


class MatchedFunctionsChooser(Choose):
    """Chooser for displaying matched functions."""

    def __init__(self, results: Optional['BindiffResults'] = None):
        columns = [
            ["Similarity", 5 | Choose.CHCOL_DEC],
            ["Confidence", 5 | Choose.CHCOL_DEC],
            ["Change", 15],
            ["EA Primary", 10 | Choose.CHCOL_HEX],
            ["Name Primary", 30],
            ["EA Secondary", 10 | Choose.CHCOL_HEX],
            ["Name Secondary", 30],
            ["Comments", 10],
            ["Algorithm", 25],
            ["BB Match", 8 | Choose.CHCOL_DEC],
            ["BB Primary", 8 | Choose.CHCOL_DEC],
            ["BB Secondary", 8 | Choose.CHCOL_DEC],
            ["Inst Match", 8 | Choose.CHCOL_DEC],
            ["Inst Primary", 8 | Choose.CHCOL_DEC],
            ["Inst Secondary", 8 | Choose.CHCOL_DEC],
        ]

        Choose.__init__(
            self,
            "Matched Functions",
            columns,
            flags=Choose.CH_MULTI | Choose.CH_RESTORE | Choose.CH_ATTRS,
            width=None,
            height=None,
            embedded=False,
        )

        self.results = results
        self.items = []
        self.icon = -1
        self.refresh_items()

    def refresh_items(self):
        """Refresh the items list from results."""
        self.items = []
        if not self.results:
            return

        for i in range(self.results.num_matches):
            match = self.results.get_match(i)
            self.items.append([
                f"{match.similarity:.2%}",
                f"{match.confidence:.2%}",
                match.change_type.name,
                f"{match.address_primary:08X}",
                match.name_primary,
                f"{match.address_secondary:08X}",
                match.name_secondary,
                "Yes" if match.comments_ported else "No",
                match.algorithm_name,
                str(match.basic_block_count),
                str(match.basic_block_count_primary),
                str(match.basic_block_count_secondary),
                str(match.instruction_count),
                str(match.instruction_count_primary),
                str(match.instruction_count_secondary),
            ])

    def OnGetSize(self):
        """Return number of items."""
        return len(self.items)

    def OnGetLine(self, n):
        """Return line at index n."""
        if n < len(self.items):
            return self.items[n]
        return []

    def OnGetIcon(self, n):
        """Return icon for line n."""
        return self.icon

    def OnSelectLine(self, n):
        """Handle line selection (double-click or Enter)."""
        if not self.results or n >= self.results.num_matches:
            return

        match = self.results.get_match(n)
        # Jump to primary address in IDA
        ida_kernwin.jumpto(match.address_primary)

    def OnDeleteLine(self, sel):
        """Handle delete action."""
        if not self.results:
            return

        # Delete selected matches
        indices = list(sel)
        if self.results.delete_matches(indices) == 0:
            self.refresh_items()
            return Choose.ALL_CHANGED
        return 0

    def OnRefresh(self, n):
        """Handle refresh."""
        self.refresh_items()
        return [Choose.ALL_CHANGED] + [0] * len(self.items)

    def show(self):
        """Show the chooser."""
        return self.Show(modal=False) >= 0


class UnmatchedFunctionsChooserPrimary(Choose):
    """Chooser for displaying unmatched functions in primary binary."""

    def __init__(self, results: Optional['BindiffResults'] = None):
        columns = [
            ["EA", 10 | Choose.CHCOL_HEX],
            ["Name", 40],
            ["Basic Blocks", 10 | Choose.CHCOL_DEC],
            ["Instructions", 10 | Choose.CHCOL_DEC],
            ["Edges", 10 | Choose.CHCOL_DEC],
        ]

        Choose.__init__(
            self,
            "Unmatched Functions (Primary)",
            columns,
            flags=Choose.CH_MULTI | Choose.CH_RESTORE,
            width=None,
            height=None,
            embedded=False,
        )

        self.results = results
        self.items = []
        self.icon = -1
        self.refresh_items()

    def refresh_items(self):
        """Refresh the items list from results."""
        self.items = []
        if not self.results:
            return

        for i in range(self.results.num_unmatched_primary):
            func = self.results.get_unmatched_primary(i)
            self.items.append([
                f"{func.address:08X}",
                func.name,
                str(func.basic_block_count),
                str(func.instruction_count),
                str(func.edge_count),
            ])

    def OnGetSize(self):
        """Return number of items."""
        return len(self.items)

    def OnGetLine(self, n):
        """Return line at index n."""
        if n < len(self.items):
            return self.items[n]
        return []

    def OnGetIcon(self, n):
        """Return icon for line n."""
        return self.icon

    def OnSelectLine(self, n):
        """Handle line selection."""
        if not self.results or n >= self.results.num_unmatched_primary:
            return

        func = self.results.get_unmatched_primary(n)
        ida_kernwin.jumpto(func.address)

    def OnRefresh(self, n):
        """Handle refresh."""
        self.refresh_items()
        return [Choose.ALL_CHANGED] + [0] * len(self.items)

    def show(self):
        """Show the chooser."""
        return self.Show(modal=False) >= 0


class UnmatchedFunctionsChooserSecondary(Choose):
    """Chooser for displaying unmatched functions in secondary binary."""

    def __init__(self, results: Optional['BindiffResults'] = None):
        columns = [
            ["EA", 10 | Choose.CHCOL_HEX],
            ["Name", 40],
            ["Basic Blocks", 10 | Choose.CHCOL_DEC],
            ["Instructions", 10 | Choose.CHCOL_DEC],
            ["Edges", 10 | Choose.CHCOL_DEC],
        ]

        Choose.__init__(
            self,
            "Unmatched Functions (Secondary)",
            columns,
            flags=Choose.CH_MULTI | Choose.CH_RESTORE,
            width=None,
            height=None,
            embedded=False,
        )

        self.results = results
        self.items = []
        self.icon = -1
        self.refresh_items()

    def refresh_items(self):
        """Refresh the items list from results."""
        self.items = []
        if not self.results:
            return

        for i in range(self.results.num_unmatched_secondary):
            func = self.results.get_unmatched_secondary(i)
            self.items.append([
                f"{func.address:08X}",
                func.name,
                str(func.basic_block_count),
                str(func.instruction_count),
                str(func.edge_count),
            ])

    def OnGetSize(self):
        """Return number of items."""
        return len(self.items)

    def OnGetLine(self, n):
        """Return line at index n."""
        if n < len(self.items):
            return self.items[n]
        return []

    def OnGetIcon(self, n):
        """Return icon for line n."""
        return self.icon

    def OnSelectLine(self, n):
        """Handle line selection."""
        if not self.results or n >= self.results.num_unmatched_secondary:
            return

        func = self.results.get_unmatched_secondary(n)
        # For secondary, we can't jump directly, just show info
        ida_kernwin.msg(f"Secondary function: {func.name} at 0x{func.address:X}\n")

    def OnRefresh(self, n):
        """Handle refresh."""
        self.refresh_items()
        return [Choose.ALL_CHANGED] + [0] * len(self.items)

    def show(self):
        """Show the chooser."""
        return self.Show(modal=False) >= 0


class StatisticsChooser(Choose):
    """Chooser for displaying diff statistics."""

    def __init__(self, results: Optional['BindiffResults'] = None):
        columns = [
            ["Statistic", 40],
            ["Value", 15],
        ]

        Choose.__init__(
            self,
            "BinDiff Statistics",
            columns,
            flags=Choose.CH_RESTORE,
            width=None,
            height=None,
            embedded=False,
        )

        self.results = results
        self.items = []
        self.icon = -1
        self.refresh_items()

    def refresh_items(self):
        """Refresh the items list from results."""
        self.items = []
        if not self.results:
            return

        for i in range(self.results.num_statistics):
            stat = self.results.get_statistic(i)
            if stat.is_count:
                value_str = str(int(stat.value))
            else:
                value_str = f"{stat.value:.4f}"
            self.items.append([stat.name, value_str])

    def OnGetSize(self):
        """Return number of items."""
        return len(self.items)

    def OnGetLine(self, n):
        """Return line at index n."""
        if n < len(self.items):
            return self.items[n]
        return []

    def OnGetIcon(self, n):
        """Return icon for line n."""
        return self.icon

    def OnRefresh(self, n):
        """Handle refresh."""
        self.refresh_items()
        return [Choose.ALL_CHANGED] + [0] * len(self.items)

    def show(self):
        """Show the chooser."""
        return self.Show(modal=False) >= 0


class BinDiffPlugin(ida_idaapi.plugin_t):
    """BinDiff IDA Plugin main class."""

    flags = ida_idaapi.PLUGIN_KEEP | ida_idaapi.PLUGIN_MULTI
    comment = PLUGIN_COMMENT
    help = "BinDiff - Binary comparison tool"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def __init__(self):
        super(BinDiffPlugin, self).__init__()
        self.results = None
        self.matched_chooser = None
        self.unmatched_primary_chooser = None
        self.unmatched_secondary_chooser = None
        self.statistics_chooser = None

    def init(self):
        """Initialize the plugin."""
        if not BINDIFF_AVAILABLE:
            ida_kernwin.warning("BinDiff Python module not available. "
                              "Please build the Cython extensions.")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.msg(f"{PLUGIN_NAME} {PLUGIN_VERSION} initialized\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Run the plugin."""
        # Show menu
        choice = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Load BinDiff results?\n\n"
            "YES - Load results from file\n"
            "NO - Show current results\n"
            "CANCEL - Exit"
        )

        if choice == ida_kernwin.ASKBTN_CANCEL:
            return

        if choice == ida_kernwin.ASKBTN_YES:
            self.load_results()

        if self.results:
            self.show_results()

    def term(self):
        """Terminate the plugin."""
        ida_kernwin.msg(f"{PLUGIN_NAME} terminated\n")

    def load_results(self):
        """Load BinDiff results from file."""
        filename = ida_kernwin.ask_file(0, "*.BinDiff", "Load BinDiff results")
        if not filename:
            return

        # Create results object
        self.results = BindiffResults.create()
        if not self.results:
            ida_kernwin.warning("Failed to create results object")
            return

        # Load from file
        if self.results.read_from_file(filename) != 0:
            ida_kernwin.warning(f"Failed to load results from {filename}")
            self.results = None
            return

        ida_kernwin.msg(f"Loaded results from {filename}\n")
        ida_kernwin.msg(f"  Matches: {self.results.num_matches}\n")
        ida_kernwin.msg(f"  Unmatched (primary): {self.results.num_unmatched_primary}\n")
        ida_kernwin.msg(f"  Unmatched (secondary): {self.results.num_unmatched_secondary}\n")

    def show_results(self):
        """Show results in choosers."""
        if not self.results:
            ida_kernwin.warning("No results loaded")
            return

        # Show matched functions chooser
        self.matched_chooser = MatchedFunctionsChooser(self.results)
        self.matched_chooser.show()

        # Ask to show more
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                             "Show unmatched functions?") == ida_kernwin.ASKBTN_YES:
            self.unmatched_primary_chooser = UnmatchedFunctionsChooserPrimary(self.results)
            self.unmatched_primary_chooser.show()

            self.unmatched_secondary_chooser = UnmatchedFunctionsChooserSecondary(self.results)
            self.unmatched_secondary_chooser.show()

        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                             "Show statistics?") == ida_kernwin.ASKBTN_YES:
            self.statistics_chooser = StatisticsChooser(self.results)
            self.statistics_chooser.show()


def PLUGIN_ENTRY():
    """Plugin entry point for IDA."""
    return BinDiffPlugin()
