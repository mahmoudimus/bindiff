# -*- coding: utf-8 -*-
# IDA Pro Python Plugin for BinDiff (Port)

# TODO: Future Enhancements / Outstanding Items
# - Implement "Diff Database Incrementally"
#   - Requires understanding how python-bindiff handles incremental diffs or implementing logic manually.
# - Implement Delete/Confirm Match actions
#   - Requires direct database manipulation via BindiffFile API (query + delete/update).
#   - Need to figure out exact DB operations for deleting/confirming (e.g., setting algorithm to MANUAL).
# - Implement actual filtering for "Diff Database Filtered"
#   - Check if python-bindiff adds filtering options later.
#   - Alternatively, implement pre-export filtering (if possible) or post-diff filtering.
# - Add Configuration Options
#   - Differ executable path.
#   - Default filter values.
#   - Logging level/destination.
# - Address minor TODOs throughout the code.
# - Improve error handling and robustness.
# - Test thoroughly.

import logging
import os
import re
import shutil
import subprocess
import sys

import ida_bytes
import ida_expr
import ida_funcs
import ida_graph
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_pro

# Attempt to import python-bindiff
try:
    import bindiff

    # Check if the differ executable is available early
    try:
        bindiff_differ_path = bindiff.config.BINDIFF_PATH or "'differ' in PATH"
        log.info(f"Using BinDiff differ executable found at: {bindiff_differ_path}")
        bindiff.BinDiff.assert_installation_ok()
        PYTHON_BINDIFF_AVAILABLE = True
    except bindiff.types.BindiffNotFound:
        ida_kernwin.warning(
            "BinDiff 'differ' executable not found in PATH or BINDIFF_PATH environment variable. Please ensure BinDiff is installed correctly and accessible."
        )
        PYTHON_BINDIFF_AVAILABLE = False
    except Exception as e:
        ida_kernwin.warning(f"Error checking bindiff installation: {e}")
        PYTHON_BINDIFF_AVAILABLE = False
except ImportError:
    ida_kernwin.warning(
        "python-bindiff library not found. Please install it (`pip install python-bindiff`)."
    )
    PYTHON_BINDIFF_AVAILABLE = False
except Exception as e:
    ida_kernwin.warning(f"Error importing/checking python-bindiff: {e}")
    PYTHON_BINDIFF_AVAILABLE = False

# Check for python-binexport (required for diffing)
PYTHON_BINEXPORT_AVAILABLE = False
if PYTHON_BINDIFF_AVAILABLE:  # Only check if bindiff imported ok
    try:
        import binexport

        PYTHON_BINEXPORT_AVAILABLE = True
    except ImportError:
        ida_kernwin.warning(
            "python-binexport library not found. Diffing will not work. Please install it (`pip install python-binexport`)."
        )
    except Exception as e:
        ida_kernwin.warning(f"Error importing python-binexport: {e}")

# Constants
PLUGIN_NAME = "BinDiff (Python Port)"
PLUGIN_COMMENT = "Structural comparison of executable objects (Python Port)"
PLUGIN_HELP = "Python port of the BinDiff IDA Plugin"
PLUGIN_HOTKEY = "Ctrl-6"  # Same as C++ version, might conflict if both installed
PLUGIN_VERSION = "0.1.0"  # TODO: Get version dynamically?

# Globals / Plugin State
bindiff_results = None  # Will hold the bindiff.BinDiff object
bindiff_results_modified = False  # Track if changes need saving
bindiff_icon_id = -1
BINDIFF_ICON_PATH = (
    "path/to/your/bindiff_icon.png"  # <<<!!! IMPORTANT: Set this path !!!>>>
)
bindiff_hooks = None  # Global to hold hooks instance

# --- Logging ---
# TODO: Configure logging properly (file, stderr based on config)
log = logging.getLogger("BinDiffPlugin")
# Example basic config, refine later
log.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
log.addHandler(handler)


# --- Actions ---

ACTION_SHOW_MATCHED = "bindiff:show_matched"
ACTION_SHOW_UNMATCHED_PRIMARY = "bindiff:show_primary_unmatched"
ACTION_SHOW_UNMATCHED_SECONDARY = "bindiff:show_secondary_unmatched"
ACTION_SHOW_STATISTICS = "bindiff:show_statistics"
ACTION_DIFF_DATABASE = "bindiff:diff_database"
ACTION_LOAD_RESULTS = "bindiff:load_results"
ACTION_VIEW_FLOW_GRAPHS = "bindiff:view_flow_graphs"
ACTION_SAVE_RESULTS = "bindiff:save_results"
ACTION_PORT_COMMENTS = "bindiff:port_comments"
ACTION_ADD_MATCH = "bindiff:add_match"
ACTION_DELETE_MATCH = "bindiff:delete_match"
ACTION_CONFIRM_MATCH = "bindiff:confirm_match"
ACTION_DIFF_DATABASE_FILTERED = "bindiff:diff_database_filtered"


class ShowMatchedActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if bindiff_results:
            MatchedFunctionsChooser.show()
        else:
            ida_kernwin.warning("No BinDiff results loaded.")
        return 1  # Handled

    def update(self, ctx):
        # Action is enabled only if results are loaded
        return ida_kernwin.AST_ENABLE if bindiff_results else ida_kernwin.AST_DISABLE


class ShowUnmatchedPrimaryActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if bindiff_results:
            UnmatchedFunctionsChooserPrimary.show()
        else:
            ida_kernwin.warning("No BinDiff results loaded.")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE if bindiff_results else ida_kernwin.AST_DISABLE


class ShowUnmatchedSecondaryActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if bindiff_results:
            UnmatchedFunctionsChooserSecondary.show()
        else:
            ida_kernwin.warning("No BinDiff results loaded.")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE if bindiff_results else ida_kernwin.AST_DISABLE


class ShowStatisticsActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if bindiff_results:
            StatisticsChooser.show()
        else:
            ida_kernwin.warning("No BinDiff results loaded.")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE if bindiff_results else ida_kernwin.AST_DISABLE


class DiffDatabaseActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        diff_database()
        return 1  # Handled

    def update(self, ctx):
        # Always enable if an IDB is open?
        return (
            ida_kernwin.AST_ENABLE
            if ida_nalt.get_input_file_path()
            else ida_kernwin.AST_DISABLE_FOR_IDB
        )


class DiffDatabaseFilteredActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # TODO: Implement filtering dialog and pass filters to diffing function
        log.warning(
            "'Diff Database Filtered' currently behaves the same as 'Diff Database'. Filtering not yet implemented."
        )
        ida_kernwin.warning("Filtering options are not yet implemented for diffing.")
        diff_database()  # Call the standard diff for now
        return 1  # Handled

    def update(self, ctx):
        # Enable if IDB is open
        return (
            ida_kernwin.AST_ENABLE
            if ida_nalt.get_input_file_path()
            else ida_kernwin.AST_DISABLE_FOR_IDB
        )


class LoadResultsActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        load_bindiff_results()  # Call existing helper
        # Refresh choosers maybe?
        refresh_all_choosers()
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if ida_nalt.get_input_file_path()
            else ida_kernwin.AST_DISABLE_FOR_IDB
        )


class ViewFlowGraphsActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, chooser):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser  # Keep reference to the chooser instance

    def activate(self, ctx):
        if not self.chooser or not bindiff_results:
            return 0

        selections = ctx.chooser_selection
        if not selections or len(selections) != 1:
            log.warning("Visual diff requires exactly one match selection.")
            return 0

        idx = selections[0]
        if idx < 0 or idx >= len(self.chooser.items):
            log.error(f"Invalid selection index {idx} for visual diff.")
            return 0

        try:
            # Get the stored function/match objects
            func1, func2, match_obj = self.chooser.items[idx][-1]
            log.info(f"Initiating visual diff for: {func1.name} <-> {func2.name}")
            show_visual_diff(func1, func2)
        except Exception as e:
            log.error(f"Failed to start visual diff: {e}", exc_info=True)
            ida_kernwin.warning(f"Error starting visual diff:\n{e}")

        return 1  # Handled

    def update(self, ctx):
        # Enable only when exactly one item is selected in the specific chooser instance
        if ctx.widget == self.chooser.GetWidget() and len(ctx.chooser_selection) == 1:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET


class SaveResultsActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        save_bindiff_results()
        return 1  # Handled

    def update(self, ctx):
        # Enable only if results are loaded and ideally, modified?
        # For now, enable if results exist.
        return ida_kernwin.AST_ENABLE if bindiff_results else ida_kernwin.AST_DISABLE


# --- Filtering Form for Porting ---
class PortFilterForm(ida_kernwin.Form):
    def __init__(self):
        self.min_similarity = ida_kernwin.Form.NumericInput(
            tp=ida_kernwin.Form.FT_FLOAT, value=0.0
        )
        self.min_confidence = ida_kernwin.Form.NumericInput(
            tp=ida_kernwin.Form.FT_FLOAT, value=0.0
        )
        form_str = f"""STARTITEM 0
BUTTON YES OK
BUTTON CANCEL Cancel
HELP
Enter minimum similarity and confidence values to filter which matches are used for porting symbols and comments.
ENDHELP
Filter Porting

Minimum Similarity (0.0 - 1.0):
<#Enter minimum similarity value#:{self.min_similarity.id}>

Minimum Confidence (0.0 - 1.0):
<#Enter minimum confidence value#:{self.min_confidence.id}>
"""
        ida_kernwin.Form.__init__(
            self,
            form_str,
            {
                "NumericInput": ida_kernwin.Form.GroupControl(
                    (self.min_similarity, self.min_confidence)
                )
            },
        )

    @staticmethod
    def show():
        form = PortFilterForm()
        form.Compile()
        ok = form.Execute()
        if ok == 1:
            sim = form.min_similarity.value
            conf = form.min_confidence.value
            # Clamp values
            sim = max(0.0, min(1.0, sim))
            conf = max(0.0, min(1.0, conf))
            form.Free()
            return sim, conf
        form.Free()
        return None, None


class PortCommentsActionHandler(ida_kernwin.action_handler_t):
    # This handler could be context-aware (attached to chooser) or global (attached to menu)
    # Let's make it global for now, similar to one of the C++ options.
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not bindiff_results:
            ida_kernwin.warning("No BinDiff results loaded.")
            return 0

        # Show filtering dialog
        min_sim, min_conf = PortFilterForm.show()

        if min_sim is None:  # User cancelled
            log.info("Porting cancelled by user.")
            return 0

        log.info(
            f"Porting all matches with min similarity >= {min_sim} and min confidence >= {min_conf}"
        )
        port_comments_symbols(
            use_selection=False,
            selection_indices=None,
            min_similarity=min_sim,
            min_confidence=min_conf,
        )
        return 1  # Handled

    def update(self, ctx):
        # Enable if results are loaded
        return ida_kernwin.AST_ENABLE if bindiff_results else ida_kernwin.AST_DISABLE


class PortCommentsSelectionActionHandler(ida_kernwin.action_handler_t):
    # Handler specifically for chooser context menu
    def __init__(self, chooser):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser

    def activate(self, ctx):
        if not self.chooser or not bindiff_results:
            return 0

        selections = ctx.chooser_selection
        if not selections:
            ida_kernwin.warning("No matches selected to port comments/symbols from.")
            return 0

        port_comments_symbols(use_selection=True, selection_indices=selections)
        return 1  # Handled

    def update(self, ctx):
        # Enable only when items are selected in the specific chooser instance
        if ctx.widget == self.chooser.GetWidget() and ctx.chooser_selection:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET


class AddMatchActionHandler(ida_kernwin.action_handler_t):
    # Attached to context menu of Unmatched choosers
    def __init__(self, chooser, is_primary_chooser):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser
        self.is_primary_chooser = is_primary_chooser

    def activate(self, ctx):
        global bindiff_results, bindiff_results_modified
        if not self.chooser or not bindiff_results:
            return 0

        selections = ctx.chooser_selection
        if not selections or len(selections) != 1:
            log.warning("Add match requires exactly one function selection.")
            return 0

        idx = selections[0]
        if idx < 0 or idx >= len(self.chooser.items):
            return 0

        selected_func = self.chooser.items[idx][-1]  # Get the FunctionBinExport object
        selected_func_addr = selected_func.addr

        # Prompt user to select the corresponding function from the *other* unmatched list
        target_func_addr = None
        if self.is_primary_chooser:
            # Show secondary unmatched list
            secondary_chooser = UnmatchedFunctionsChooserSecondary(
                title="Select Secondary Function to Match"
            )
            chosen_idx = secondary_chooser.Show(True)  # Show modal
            if chosen_idx >= 0:
                target_func_addr = secondary_chooser.items[chosen_idx][-1].addr
            primary_func_addr = selected_func_addr
        else:  # Secondary chooser context
            # Show primary unmatched list
            primary_chooser = UnmatchedFunctionsChooserPrimary(
                title="Select Primary Function to Match"
            )
            chosen_idx = primary_chooser.Show(True)  # Show modal
            if chosen_idx >= 0:
                target_func_addr = primary_chooser.items[chosen_idx][-1].addr
            secondary_func_addr = selected_func_addr
            primary_func_addr = target_func_addr  # Reassign for clarity below
            target_func_addr = (
                secondary_func_addr  # Make target_func_addr always the secondary
            )

        if target_func_addr is None:
            log.info("Add match cancelled by user.")
            return 0

        log.info(
            f"Attempting to add manual match: {primary_func_addr:#x} <-> {target_func_addr:#x}"
        )
        try:
            # --- How to add a match with python-bindiff? --- Check API! ---
            # Does bindiff_results object have an add_match(func1_addr, func2_addr) method?
            # If not, this is very complex. We'd need to modify the underlying SQLite DB.
            log.error(
                "Adding matches not implemented in python-bindiff (assumed). Cannot add match."
            )
            ida_kernwin.warning("Adding matches is not supported by this plugin yet.")
            # bindiff_results.add_match(primary_func_addr, target_func_addr) # Hypothetical
            # bindiff_results_modified = True
            # refresh_all_choosers()

            # We need to access the underlying BindiffFile object to modify matches.
            # Assuming it's stored in `_primary_diff` (or similar)
            if (
                not hasattr(bindiff_results, "_primary_diff")
                or not bindiff_results._primary_diff
            ):
                log.error("Cannot access internal BindiffFile object to add match.")
                ida_kernwin.warning(
                    "Adding matches requires internal DB access, which failed."
                )
                return 1

            db_file: bindiff.file.BindiffFile = bindiff_results._primary_diff

            # We also need the function names for add_function_match
            # Get the FunctionBinExport objects corresponding to the addresses
            primary_func = bindiff_results.primary.get_function(primary_func_addr)
            secondary_func = bindiff_results.secondary.get_function(target_func_addr)

            if not primary_func or not secondary_func:
                log.error(
                    f"Could not find function objects for {primary_func_addr:#x} or {target_func_addr:#x}"
                )
                ida_kernwin.warning("Could not find function objects for match.")
                return 1

            # Add the match - what similarity/confidence should be used for manual matches?
            # Use 1.0 for both? Or make it configurable?
            # For now, use 1.0 and 1.0. Note: add_function_match requires names!
            log.warning(
                "`BindiffFile.add_function_match` API does not support setting algorithm or identical BB count. Manual matches may lack this info."
            )
            match_id = db_file.add_function_match(
                fun_addr1=primary_func_addr,
                fun_addr2=target_func_addr,
                fun_name1=primary_func.name or f"sub_{primary_func_addr:x}",
                fun_name2=secondary_func.name or f"sub_{target_func_addr:x}",
                similarity=1.0,
                confidence=1.0,
                # algorithm=? Missing from add_function_match? Default?
                # identical_bbs=? Missing from add_function_match? Default?
            )
            log.info(f"Added function match with DB ID: {match_id}")
            bindiff_results_modified = True  # Mark as modified (DB change)
            # Reload or refresh the BinDiff object? The API docs say the BinDiff object
            # might need reloading after DB changes, or maybe internal state updates?
            # For now, just refresh choosers. This might show stale data until reload.
            # TODO: Investigate how python-bindiff handles DB changes after load.
            refresh_all_choosers()
        except Exception as e:
            log.error(f"Failed to add match: {e}", exc_info=True)
            ida_kernwin.warning(f"Error adding match:\n{e}")

        return 1

    def update(self, ctx):
        # Enable only when exactly one item is selected
        if ctx.widget == self.chooser.GetWidget() and len(ctx.chooser_selection) == 1:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET


class DeleteMatchActionHandler(ida_kernwin.action_handler_t):
    # Attached to context menu of Matched chooser
    def __init__(self, chooser):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser

    def activate(self, ctx):
        global bindiff_results, bindiff_results_modified
        if not self.chooser or not bindiff_results:
            return 0

        selections = ctx.chooser_selection
        if not selections:
            log.warning("No matches selected for deletion.")
            return 0

        func_pairs_to_delete = []
        for idx in selections:
            if 0 <= idx < len(self.chooser.items):
                func1, func2, match_obj = self.chooser.items[idx][-1]
                func_pairs_to_delete.append((func1.addr, func2.addr))

        log.info(f"Attempting to delete {len(func_pairs_to_delete)} matches...")
        try:
            # --- How to delete matches with python-bindiff? --- Check API! ---
            # Does bindiff_results object have a delete_match(func1_addr, func2_addr) or similar?
            log.error(
                "Deleting matches not implemented in python-bindiff (assumed). Cannot delete match."
            )
            ida_kernwin.warning("Deleting matches is not supported by this plugin yet.")
            # for p_addr, s_addr in func_pairs_to_delete:
            #     bindiff_results.delete_match(p_addr, s_addr) # Hypothetical
            # bindiff_results_modified = True
            # refresh_all_choosers()

            # Need BindiffFile access
            if (
                not hasattr(bindiff_results, "_primary_diff")
                or not bindiff_results._primary_diff
            ):
                log.error("Cannot access internal BindiffFile object to delete match.")
                ida_kernwin.warning(
                    "Deleting matches requires internal DB access, which failed."
                )
                return 1

            db_file: bindiff.file.BindiffFile = bindiff_results._primary_diff

            # python-bindiff API (via BindiffFile) doesn't expose a simple delete_match.
            # We'd need to find the match ID in the function_matches table and delete it.
            # This requires more complex DB interaction (querying by address pair, then deleting by ID).

            log.error(
                "Deleting matches requires direct DB manipulation via BindiffFile, which is complex and not implemented in this plugin."
            )
            ida_kernwin.warning("Deleting matches is not supported by this plugin yet.")
            # TODO: Implement DB query and delete if needed.

            # Placeholder for future:
            # deleted_count = 0
            # for p_addr, s_addr in func_pairs_to_delete:
            #     # Find match ID based on p_addr, s_addr
            #     # db_file.delete_function_match(match_id) # Hypothetical
            #     # deleted_count += 1
            # if deleted_count > 0:
            #      bindiff_results_modified = True
            #      refresh_all_choosers()

        except Exception as e:
            log.error(f"Failed to delete matches: {e}", exc_info=True)
            ida_kernwin.warning(f"Error deleting matches:\n{e}")

        return 1

    def update(self, ctx):
        # Enable only when items are selected
        if ctx.widget == self.chooser.GetWidget() and ctx.chooser_selection:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ConfirmMatchActionHandler(ida_kernwin.action_handler_t):
    # Attached to context menu of Matched chooser
    def __init__(self, chooser):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser

    def activate(self, ctx):
        global bindiff_results, bindiff_results_modified
        if not self.chooser or not bindiff_results:
            return 0

        selections = ctx.chooser_selection
        if not selections:
            log.warning("No matches selected for confirmation.")
            return 0

        func_pairs_to_confirm = []
        for idx in selections:
            if 0 <= idx < len(self.chooser.items):
                func1, func2, match_obj = self.chooser.items[idx][-1]
                func_pairs_to_confirm.append((func1.addr, func2.addr))

        log.info(f"Attempting to confirm {len(func_pairs_to_confirm)} matches...")
        try:
            # --- How to confirm matches with python-bindiff? --- Check API! ---
            # Mark as manual? Update algorithm?
            log.error(
                "Confirming matches not implemented in python-bindiff (assumed). Cannot confirm match."
            )
            ida_kernwin.warning(
                "Confirming matches is not supported by this plugin yet."
            )
            # for p_addr, s_addr in func_pairs_to_confirm:
            #     bindiff_results.confirm_match(p_addr, s_addr) # Hypothetical
            # bindiff_results_modified = True
            # refresh_all_choosers()

            # Need BindiffFile access
            if (
                not hasattr(bindiff_results, "_primary_diff")
                or not bindiff_results._primary_diff
            ):
                log.error("Cannot access internal BindiffFile object to confirm match.")
                ida_kernwin.warning(
                    "Confirming matches requires internal DB access, which failed."
                )
                return 1

            db_file: bindiff.file.BindiffFile = bindiff_results._primary_diff

            # python-bindiff API (via BindiffFile) doesn't expose a simple confirm_match or set_algorithm.
            # Confirmation likely means changing the algorithm field to MANUAL.
            # This requires finding the match ID, then updating the row.

            log.error(
                "Confirming matches requires direct DB manipulation via BindiffFile (updating algorithm), which is complex and not implemented in this plugin."
            )
            ida_kernwin.warning(
                "Confirming matches is not supported by this plugin yet."
            )
            # TODO: Implement DB query and update if needed.

            # Placeholder for future:
            # confirmed_count = 0
            # for p_addr, s_addr in func_pairs_to_confirm:
            #     # Find match ID based on p_addr, s_addr
            #     # db_file.update_function_match(match_id, algorithm=FunctionAlgorithm.manual) # Hypothetical
            #     # confirmed_count += 1
            # if confirmed_count > 0:
            #      bindiff_results_modified = True
            #      refresh_all_choosers()

        except Exception as e:
            log.error(f"Failed to confirm matches: {e}", exc_info=True)
            ida_kernwin.warning(f"Error confirming matches:\n{e}")

        return 1

    def update(self, ctx):
        # Enable only when items are selected
        if ctx.widget == self.chooser.GetWidget() and ctx.chooser_selection:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET


# --- Plugin Class ---


class BinDiffPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_FIX
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        global bindiff_icon_id, bindiff_hooks
        if not PYTHON_BINDIFF_AVAILABLE or not PYTHON_BINEXPORT_AVAILABLE:
            log.error("BinDiff dependencies not met. Plugin will not load.")
            return ida_idaapi.PLUGIN_SKIP

        log.info(f"{PLUGIN_NAME} v{PLUGIN_VERSION} initialized.")

        # Load the icon
        try:
            # Check if the specified path exists
            # Note: This basic check might not work if IDA runs from a different CWD.
            # A more robust solution might involve finding the plugin directory.
            if os.path.exists(BINDIFF_ICON_PATH):
                bindiff_icon_id = ida_kernwin.load_custom_icon(
                    filename=BINDIFF_ICON_PATH
                )
                if bindiff_icon_id == -1:
                    log.warning(
                        f"Failed to load icon from {BINDIFF_ICON_PATH}. Check format/permissions."
                    )
                else:
                    log.info(f"Loaded BinDiff icon (ID: {bindiff_icon_id})")
            else:
                log.warning(f"BinDiff icon file not found at: {BINDIFF_ICON_PATH}")
        except Exception as e:
            log.error(f"Error loading BinDiff icon: {e}", exc_info=True)

        # --- Register Actions ---
        # Actions that appear in main menus or have global shortcuts
        menu_actions = [
            (
                ACTION_SHOW_MATCHED,
                "~M~atched functions",
                ShowMatchedActionHandler(),
                None,
                "Show matched functions from BinDiff results",
            ),
            (
                ACTION_SHOW_UNMATCHED_PRIMARY,
                "~P~rimary unmatched",
                ShowUnmatchedPrimaryActionHandler(),
                None,
                "Show unmatched functions in the primary binary",
            ),
            (
                ACTION_SHOW_UNMATCHED_SECONDARY,
                "~S~econdary unmatched",
                ShowUnmatchedSecondaryActionHandler(),
                None,
                "Show unmatched functions in the secondary binary",
            ),
            (
                ACTION_SHOW_STATISTICS,
                "S~t~atistics",
                ShowStatisticsActionHandler(),
                None,
                "Show BinDiff statistics",
            ),
            (
                ACTION_DIFF_DATABASE,
                "Bin~D~iff...",
                DiffDatabaseActionHandler(),
                "Shift-D",
                "Diff current IDB against another binary",
            ),
            (
                ACTION_DIFF_DATABASE_FILTERED,
                "Diff Database ~F~iltered...",
                DiffDatabaseFilteredActionHandler(),
                None,
                "Diff specific address ranges (Not Yet Implemented)",
            ),
            (
                ACTION_LOAD_RESULTS,
                "~L~oad BinDiff Results...",
                LoadResultsActionHandler(),
                "Ctrl-Shift-6",
                "Load existing BinDiff results file",
            ),
            (
                ACTION_SAVE_RESULTS,
                "Save ~B~inDiff Results...",
                SaveResultsActionHandler(),
                None,
                "Save current BinDiff results to a .BinDiff file",
            ),
            (
                ACTION_PORT_COMMENTS,
                "Im~p~ort Symbols/Comments...",
                PortCommentsActionHandler(),
                None,
                "Port names and comments from secondary based on matches",
            ),
        ]

        # Actions used only in context menus (no global registration needed for the *action itself*,
        # but handlers are created here to be attached later)
        # Note: We create dummy handlers here just to hold the class type. The real handlers
        # with the chooser instance are created dynamically in OnGetPopupMenu.
        self._view_flow_graphs_handler_type = ViewFlowGraphsActionHandler
        self._port_selection_handler_type = PortCommentsSelectionActionHandler
        self._add_match_handler_type = AddMatchActionHandler
        self._delete_match_handler_type = DeleteMatchActionHandler
        self._confirm_match_handler_type = ConfirmMatchActionHandler

        for name, label, handler, shortcut, tooltip in menu_actions:
            if not ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    name, label, handler, shortcut, tooltip, bindiff_icon_id
                )
            ):
                log.error(f"Failed to register action: {name}")

        # --- Register Menus ---
        # ... (Attach MENU actions only)
        try:
            # View Menu Items
            ida_kernwin.create_menu(
                "bindiff_view_menu", "BinDiff", "View/Open subviews/"
            )  # Renamed menu key slightly
            ida_kernwin.attach_action_to_menu(
                "View/BinDiff/", ACTION_SHOW_MATCHED, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_menu(
                "View/BinDiff/", ACTION_SHOW_UNMATCHED_PRIMARY, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_menu(
                "View/BinDiff/",
                ACTION_SHOW_UNMATCHED_SECONDARY,
                ida_kernwin.SETMENU_APP,
            )
            ida_kernwin.attach_action_to_menu(
                "View/BinDiff/", ACTION_SHOW_STATISTICS, ida_kernwin.SETMENU_APP
            )

            # Edit Menu Item (Global Port)
            ida_kernwin.attach_action_to_menu(
                "Edit/BinDiff Porting/", ACTION_PORT_COMMENTS, ida_kernwin.SETMENU_APP
            )

            # File Menu Items (or maybe Tools?)
            ida_kernwin.create_menu("bindiff_file_menu", "BinDiff", "File/")
            ida_kernwin.attach_action_to_menu(
                "File/BinDiff/", ACTION_DIFF_DATABASE, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_menu(
                "File/BinDiff/", ACTION_DIFF_DATABASE_FILTERED, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_menu(
                "File/BinDiff/", ACTION_LOAD_RESULTS, ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_menu(
                "File/BinDiff/", ACTION_SAVE_RESULTS, ida_kernwin.SETMENU_APP
            )

            log.info("Registered BinDiff menu and actions.")
        except Exception as e:
            log.error(f"Failed to register menus/actions: {e}")

        # --- Register Hooks --- #
        try:
            bindiff_hooks = BinDiffIDPHooks()
            if bindiff_hooks.hook():
                log.info("Registered BinDiff IDP hooks.")
            else:
                log.error("Failed to register BinDiff IDP hooks.")
                bindiff_hooks = None  # Clear if hook failed
        except Exception as e:
            log.error(f"Failed to register hooks: {e}", exc_info=True)

        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        global bindiff_hooks
        log.info(f"{PLUGIN_NAME} terminated.")
        # Check save on term - This is tricky, IDB save might happen before/after term.
        # Relying on savebase hook is likely better.
        # if not prompt_save_if_modified():
        #     log.warning("Termination proceeding after user cancelled saving modified results.")

        # --- Unregister Hooks --- #
        if bindiff_hooks:
            try:
                if bindiff_hooks.unhook():
                    log.info("Unregistered BinDiff IDP hooks.")
                else:
                    log.error("Failed to unregister BinDiff IDP hooks.")
            except Exception as e:
                log.error(f"Error unregistering hooks: {e}", exc_info=True)
            bindiff_hooks = None

        # --- Unregister Menus --- #
        try:
            ida_kernwin.delete_menu("bindiff_view_menu")
            ida_kernwin.delete_menu("bindiff_file_menu")
            # Detach actions attached outside deleted menus
            ida_kernwin.detach_action_from_menu(
                "Edit/BinDiff Porting/", ACTION_PORT_COMMENTS
            )
            ida_kernwin.delete_menu("Edit/BinDiff Porting/")  # Delete submenu if empty
        except Exception as e:
            log.error(f"Failed to unregister menus: {e}")

        # --- Unregister Actions --- #
        # Unregister only the globally registered actions
        actions_to_unregister = [
            ACTION_SHOW_MATCHED,
            ACTION_SHOW_UNMATCHED_PRIMARY,
            ACTION_SHOW_UNMATCHED_SECONDARY,
            ACTION_SHOW_STATISTICS,
            ACTION_DIFF_DATABASE,
            ACTION_LOAD_RESULTS,
            ACTION_VIEW_FLOW_GRAPHS,  # Keep this? ViewFlowGraphs handler was attached in init?
            ACTION_SAVE_RESULTS,
            ACTION_PORT_COMMENTS,
            ACTION_DIFF_DATABASE_FILTERED,
            # Context menu actions (Add/Delete/Confirm/PortSelection) were not globally registered.
        ]
        for action_name in actions_to_unregister:
            if not ida_kernwin.unregister_action(action_name):
                log.error(f"Failed to unregister action: {action_name}")
        # TODO: Unregister other actions

        # TODO: Unregister hooks
        # TODO: Prompt to save results if modified
        global bindiff_results, bindiff_results_modified
        bindiff_results = None
        bindiff_results_modified = False

    def run(self, arg):
        log.info(f"{PLUGIN_NAME} run() called with arg: {arg}")

        if not PYTHON_BINDIFF_AVAILABLE:
            ida_kernwin.warning("BinDiff dependencies not met. Cannot run.")
            return False

        # TODO: Check if BinExport is available (how? maybe check for binexport python lib?)
        # TODO: Check if IDB is open

        # Check if results are loaded and if the IDB hash matches
        global bindiff_results
        if bindiff_results:
            try:
                current_hash = ida_nalt.retrieve_input_file_sha256()
                if not current_hash:  # Fallback to MD5
                    current_hash = ida_nalt.retrieve_input_file_md5()

                # python-bindiff stores ProgramBinExport objects in primary/secondary
                # Assuming python-binexport stores hash like the C++ version
                primary_hash_in_results = (
                    bindiff_results.primary.hash
                )  # Check attribute name!
                log.debug(
                    f"Current IDB hash: {current_hash}, Results primary hash: {primary_hash_in_results}"
                )

                if (
                    current_hash
                    and primary_hash_in_results
                    and current_hash.lower() != primary_hash_in_results.lower()
                ):
                    ida_kernwin.warning(
                        "Current IDB does not match the primary binary in the loaded BinDiff results. Discarding results."
                    )
                    # TODO: Add prompt to save before discarding?
                    bindiff_results = None
            except AttributeError:
                log.warning(
                    "Could not get hash from loaded BinDiff results primary object. Assuming mismatch."
                )
                bindiff_results = None
            except Exception as e:
                log.error(f"Error checking IDB hash against results: {e}")
                # Decide whether to discard results or proceed with caution
                bindiff_results = None  # Safer to discard

        # --- Main Dialog ---
        if bindiff_results:
            # Dialog shown when results ARE loaded
            dialog_text = f"""STARTITEM 0
BUTTON YES Close
BUTTON CANCEL NONE
HELP
'Diff Database...' diff the currently open IDB against another one.
'Diff Database Filtered...' diff specific address ranges.
'Diff Database Incrementally' keep manually confirmed matches and re-match others.
'Load Results...' load a previously saved diff result.
'Save Results...' save the current BinDiff matching.
'Import Symbols and Comments...' copy data from secondary to primary.
ENDHELP
{PLUGIN_NAME} {PLUGIN_VERSION}

<~D~iff Database...:B:1:30::>
<D~i~ff Database Filtered...:B:1:30::>
<Diff Database Incrementally:B:1:30::>

<L~o~ad Results...:B:1:30::>
<~S~ave Results...:B:1:30::>

<Im~p~ort Symbols and Comments...:B:1:30::>
"""

            # Define callbacks for this dialog
            # TODO: Implement these callbacks
            class DiffDbForm(ida_kernwin.Form):
                def __init__(self):
                    # Define controls based on dialog_text button order
                    controls = [
                        ida_kernwin.Form.ButtonInput(self.on_diff_db),
                        ida_kernwin.Form.ButtonInput(self.on_diff_filtered),
                        ida_kernwin.Form.ButtonInput(self.on_rediff),
                        ida_kernwin.Form.ButtonInput(self.on_load_results),
                        ida_kernwin.Form.ButtonInput(self.on_save_results),
                        ida_kernwin.Form.ButtonInput(self.on_port_comments),
                    ]
                    ida_kernwin.Form.__init__(
                        self, dialog_text, {"ButtonInput": controls}
                    )

                def on_diff_db(self, code=0):
                    log.info("Diff DB clicked")
                    self.Close(1)

                def on_diff_filtered(self, code=0):
                    log.info("Diff Filtered clicked")
                    # Activate the action handler which currently calls diff_database()
                    ida_kernwin.process_action(ACTION_DIFF_DATABASE_FILTERED)
                    self.Close(1)

                def on_rediff(self, code=0):
                    log.info("Rediff clicked - Not Implemented")
                    ida_kernwin.warning("Incremental diffing not yet implemented.")
                    self.Close(1)

                def on_load_results(self, code=0):
                    log.info("Load Results clicked")
                    load_bindiff_results()  # Call the load function
                    self.Close(1)  # Close dialog after attempting load

                def on_save_results(self, code=0):
                    log.info("Save Results clicked")
                    self.Close(1)

                def on_port_comments(self, code=0):
                    log.info("Port Comments clicked")
                    # Activate the global port action handler
                    ida_kernwin.process_action(ACTION_PORT_COMMENTS)
                    self.Close(1)

            form = DiffDbForm()
            form.Compile()
            form.Execute()

        else:
            # Dialog shown when results are NOT loaded
            dialog_text = f"""STARTITEM 0
BUTTON YES Close
BUTTON CANCEL NONE
HELP
'Diff Database...' diff the currently open IDB against another one.
'Diff Database Filtered...' diff specific address ranges.
'Load Results...' load a previously saved diff result.
ENDHELP
{PLUGIN_NAME} {PLUGIN_VERSION}

<~D~iff Database...:B:1:30::>
<D~i~ff Database Filtered...:B:1:30::>

<L~o~ad Results...:B:1:30::>
"""

            # Define callbacks for this dialog
            class NoResultsForm(ida_kernwin.Form):
                def __init__(self):
                    controls = [
                        ida_kernwin.Form.ButtonInput(self.on_diff_db),
                        ida_kernwin.Form.ButtonInput(self.on_diff_filtered),
                        ida_kernwin.Form.ButtonInput(self.on_load_results),
                    ]
                    ida_kernwin.Form.__init__(
                        self, dialog_text, {"ButtonInput": controls}
                    )

                def on_diff_db(self, code=0):
                    log.info("Diff DB clicked")
                    self.Close(1)

                def on_diff_filtered(self, code=0):
                    log.info("Diff Filtered clicked")
                    ida_kernwin.process_action(ACTION_DIFF_DATABASE_FILTERED)
                    self.Close(1)

                def on_load_results(self, code=0):
                    log.info("Load Results clicked")
                    load_bindiff_results()  # Call the load function
                    self.Close(1)  # Close dialog after attempting load

            form = NoResultsForm()
            form.Compile()
            form.Execute()

        return True


# --- Helper Functions ---


def load_bindiff_results():
    """Prompts user for a .BinDiff file and loads it using python-bindiff."""
    global bindiff_results

    # TODO: Prompt to save current results if modified

    # Ask for file
    bindiff_file_path = ida_kernwin.ask_file(
        False, "*.BinDiff", "Select BinDiff Results File"
    )
    if not bindiff_file_path:
        log.info("Load results cancelled by user.")
        return False

    if not os.path.exists(bindiff_file_path):
        log.error(f"Selected BinDiff file does not exist: {bindiff_file_path}")
        ida_kernwin.warning(f"File not found: {bindiff_file_path}")
        return False

    # Ask for corresponding BinExport files (python-bindiff needs these)
    # It seems python-bindiff needs the *original* .BinExport files used to create the .BinDiff
    # It doesn't automatically find them based on the .BinDiff file? Let's assume we need to ask.
    # Alternatively, maybe BinDiff() constructor can find them if they are alongside .BinDiff? Check docs.
    # For now, let's just try loading without explicitly providing binexports, hoping it finds them
    # primary_binexport = ida_kernwin.ask_file(False, "*.BinExport", "Select Primary BinExport File")
    # if not primary_binexport: return False
    # secondary_binexport = ida_kernwin.ask_file(False, "*.BinExport", "Select Secondary BinExport File")
    # if not secondary_binexport: return False

    log.info(f"Attempting to load BinDiff results from: {bindiff_file_path}")
    ida_kernwin.show_wait_box("Loading BinDiff Results...")
    try:
        # Load the diff. Provide the paths to the BinExport files if necessary.
        # If BinDiff() requires the ProgramBinExport objects, we need python-binexport too.
        # Assuming BinDiff can take the .BinDiff path directly for loading existing results
        # According to quarkslab/python-bindiff README:
        # diff = BinDiff("sample1.BinExport", "sample2.BinExport", "diff.BinDiff") -> Needs BinExports
        # Let's try finding the BinExport files automatically first.
        # BinDiff files often store paths/hashes, maybe the lib uses those.

        # Heuristic: Look for .BinExport files with matching names next to the .BinDiff
        diff_dir = os.path.dirname(bindiff_file_path)
        diff_basename = os.path.basename(bindiff_file_path)
        # Assuming name format like primary_vs_secondary.BinDiff
        match = re.match(r"(.+)_vs_(.+)\.BinDiff", diff_basename, re.IGNORECASE)
        primary_binexport_path = None
        secondary_binexport_path = None

        if match:
            primary_name, secondary_name = match.groups()
            p_binexport = os.path.join(diff_dir, primary_name + ".BinExport")
            s_binexport = os.path.join(diff_dir, secondary_name + ".BinExport")
            if os.path.exists(p_binexport) and os.path.exists(s_binexport):
                primary_binexport_path = p_binexport
                secondary_binexport_path = s_binexport
                log.info(
                    f"Auto-detected BinExport files: {primary_binexport_path}, {secondary_binexport_path}"
                )
            else:
                log.warning(
                    "Could not auto-detect BinExport files based on .BinDiff name."
                )
        else:
            log.warning(
                "Could not parse primary/secondary names from .BinDiff filename."
            )

        if not primary_binexport_path or not secondary_binexport_path:
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(
                "Could not find corresponding .BinExport files automatically. Please select them manually."
            )
            primary_binexport_path = ida_kernwin.ask_file(
                False, "*.BinExport", "Select Primary BinExport File for Diff"
            )
            if not primary_binexport_path:
                return False
            secondary_binexport_path = ida_kernwin.ask_file(
                False, "*.BinExport", "Select Secondary BinExport File for Diff"
            )
            if not secondary_binexport_path:
                return False
            ida_kernwin.show_wait_box("Loading BinDiff Results...")

        # Now load using the found/selected paths
        bindiff_results = bindiff.BinDiff(
            primary_binexport_path, secondary_binexport_path, bindiff_file_path
        )

        # Perform hash check again after loading
        current_hash = (
            ida_nalt.retrieve_input_file_sha256() or ida_nalt.retrieve_input_file_md5()
        )
        primary_hash_in_results = (
            bindiff_results.primary.hash
        )  # Check attribute name! Might be metadata?
        primary_filename_in_results = (
            bindiff_results.primary.filename
        )  # Check attribute name!

        log.info(
            f"Loaded results. Primary: {primary_filename_in_results}, Hash: {primary_hash_in_results}"
        )

        if (
            current_hash
            and primary_hash_in_results
            and current_hash.lower() != primary_hash_in_results.lower()
        ):
            ida_kernwin.hide_wait_box()  # Hide before showing dialog
            btn = ida_kernwin.ask_buttons(
                "Continue",
                "Cancel",
                "",
                ida_kernwin.ASKBTN_BTN1,
                f"Warning: Hash Mismatch!\n\n"
                f"The currently loaded IDB hash does not match the primary binary hash stored in the BinDiff file.\n\n"
                f"  Current IDB: {current_hash}\n"
                f"  BinDiff Primary: {primary_hash_in_results} ({os.path.basename(primary_filename_in_results)})\n\n"
                f"Results may be inaccurate if you continue.",
            )
            if btn != ida_kernwin.ASKBTN_BTN1:
                log.warning("Load cancelled by user due to hash mismatch.")
                bindiff_results = None  # Discard loaded results
                return False
            # Continue if user clicked "Continue"
            ida_kernwin.show_wait_box(
                "Loading BinDiff Results..."
            )  # Show again if continuing

        log.info(
            f"Successfully loaded BinDiff results. Similarity: {bindiff_results.similarity}, Confidence: {bindiff_results.confidence}"
        )
        ida_kernwin.hide_wait_box()

        # TODO: Refresh Choosers if they are open
        # TODO: Set modified flag to False

        return True

    except bindiff.types.BindiffNotFound as e:
        log.error(f"BinDiff differ executable not found: {e}")
        ida_kernwin.warning(
            f"BinDiff differ executable not found. Please check installation.\n{e}"
        )
        bindiff_results = None
        return False
    except FileNotFoundError as e:
        log.error(f"BinExport file not found during load: {e}")
        ida_kernwin.warning(f"Required BinExport file not found during load.\n{e}")
        bindiff_results = None
        return False
    except Exception as e:
        log.error(f"Failed to load BinDiff results: {e}", exc_info=True)
        ida_kernwin.warning(f"Error loading BinDiff results:\n{e}")
        bindiff_results = None
        return False
    finally:
        if ida_pro.is_idaq():  # Check if wait box is potentially still shown
            ida_kernwin.hide_wait_box()


# --- Choosers ---


class MatchedFunctionsChooser(ida_kernwin.Choose):
    """Chooser class to display matched functions from BinDiff results."""

    def __init__(self, title=f"Matched Functions ({PLUGIN_NAME})"):
        # Note: PLUGIN_MODAL ensures the chooser is modal if shown via Show() (vs non-modal choose() in C++)
        # PLUGIN_MULTI allows multi-selection
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Similarity", 10 | ida_kernwin.Choose.CHCOL_DEC],
                ["Confidence", 10 | ida_kernwin.Choose.CHCOL_DEC],
                ["Primary Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                ["Primary Name", 30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Secondary Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                ["Secondary Name", 30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Algorithm", 15 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["BB Count", 8 | ida_kernwin.Choose.CHCOL_DEC],
                ["Edge Count", 8 | ida_kernwin.Choose.CHCOL_DEC],
                ["Inst Count", 8 | ida_kernwin.Choose.CHCOL_DEC],
            ],
            flags=ida_kernwin.Choose.CH_MULTI,
        )
        self.items = []
        self.icon = -1  # TODO: Assign icon if needed
        self.populate_items()

    def populate_items(self):
        global bindiff_results
        self.items = []
        if not bindiff_results:
            log.warning("Cannot populate MatchedFunctionsChooser: Results not loaded.")
            return

        try:
            # python-bindiff provides iter_function_matches()
            # It returns tuples: (FunctionBinExport_primary, FunctionBinExport_secondary, FunctionMatch)
            for func1, func2, match_obj in bindiff_results.iter_function_matches():
                # FunctionMatch object seems to have attributes like similarity, confidence, algorithm_id etc.
                # FunctionBinExport objects have address, name, basic_blocks, instructions etc.
                # Need to confirm exact attribute names from python-bindiff documentation/source
                # Assuming attributes based on C++ version and python-bindiff API docs:
                similarity_str = f"{match_obj.similarity:.4f}"
                confidence_str = f"{match_obj.confidence:.4f}"
                primary_addr_str = f"{func1.addr:#x}"  # Assuming 'addr'
                primary_name = (
                    func1.name if hasattr(func1, "name") else "N/A"
                )  # Assuming 'name'
                secondary_addr_str = f"{func2.addr:#x}"  # Assuming 'addr'
                secondary_name = (
                    func2.name if hasattr(func2, "name") else "N/A"
                )  # Assuming 'name'
                # Algorithm needs mapping from ID to name (python-bindiff might provide this)
                algo_name = str(match_obj.algorithm)  # Use enum name for now

                # Calculate counts from FunctionBinExport objects
                bb_count_p = (
                    len(func1.basic_blocks) if hasattr(func1, "basic_blocks") else -1
                )
                edge_count_p = (
                    sum(
                        len(bb.successors)
                        for bb in func1.basic_blocks
                        if hasattr(bb, "successors")
                    )
                    if bb_count_p != -1
                    else -1
                )
                inst_count_p = (
                    sum(
                        len(bb.instructions)
                        for bb in func1.basic_blocks
                        if hasattr(bb, "instructions")
                    )
                    if bb_count_p != -1
                    else -1
                )

                # Combine counts (or show primary only?) Let's show primary.
                bb_count_str = str(bb_count_p) if bb_count_p != -1 else "-"
                edge_count_str = str(edge_count_p) if edge_count_p != -1 else "-"
                inst_count_str = str(inst_count_p) if inst_count_p != -1 else "-"

                self.items.append(
                    [
                        similarity_str,
                        confidence_str,
                        primary_addr_str,
                        primary_name,
                        secondary_addr_str,
                        secondary_name,
                        algo_name,
                        bb_count_str,
                        edge_count_str,
                        inst_count_str,
                        # Store original objects for easy access later (e.g., in callbacks)
                        (func1, func2, match_obj),
                    ]
                )
            log.info(f"Populated MatchedFunctionsChooser with {len(self.items)} items.")
        except AttributeError as e:
            log.error(
                f"Attribute error accessing python-bindiff data: {e}. Check library API.",
                exc_info=True,
            )
            ida_kernwin.warning(f"Error accessing BinDiff data attributes: {e}")
        except Exception as e:
            log.error(f"Failed to populate MatchedFunctionsChooser: {e}", exc_info=True)
            ida_kernwin.warning(f"Failed to populate chooser: {e}")

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        # Return the displayable items (excluding the stored objects at the end)
        return self.items[n][:-1]

    def OnSelectLine(self, n):
        """Default action on double-click/enter: Show visual diff"""
        if not self.items or n >= len(self.items):
            return
        try:
            func1, func2, match_obj = self.items[n][-1]
            log.info(
                f"Default action (double-click) on match: {func1.name} <-> {func2.name}. Showing graphs."
            )
            show_visual_diff(func1, func2)
        except Exception as e:
            log.error(f"Failed to start visual diff on select: {e}", exc_info=True)
            ida_kernwin.warning(f"Error starting visual diff:\\n{e}")

    def OnDeleteLine(self, n):
        """Called when DEL key is pressed."""
        # TODO: Implement deleting a match
        ida_kernwin.warning("Delete match not yet implemented.")
        # Requires modifying bindiff_results and potentially re-saving/re-diffing
        return n  # Return index to stay on, or flags

    def OnRefresh(self, n):
        """Called when the chooser needs refreshing."""
        self.populate_items()
        # Return index to select, or -1 to preserve
        return n

    def OnActivate(self):
        """Called when the window is activated"""
        # Can be used to refresh if data might have changed externally
        # self.OnRefresh(-1)
        pass

    def OnClose(self):
        """Called when the chooser is closed."""
        log.info("MatchedFunctionsChooser closed.")
        # Clean up if needed
        pass

    def OnGetPopupMenu(self, widget, popup_handle):
        """Add context menu items."""
        # Add default actions first (Copy, etc. if defaults exist)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "-")  # Separator

        # Add our custom action
        # Need to register the action *once* in init, then attach here using the name
        ida_kernwin.attach_action_to_popup(
            widget, popup_handle, ACTION_VIEW_FLOW_GRAPHS, None
        )

        # Attach Port Comments (Selection) Action
        # Register action once in init, attach here by name
        ida_kernwin.attach_action_to_popup(
            widget, popup_handle, "bindiff:port_comments_selection", None
        )

        # Attach Add/Delete/Confirm Match actions
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "-")  # Separator
        ida_kernwin.attach_action_to_popup(
            widget, popup_handle, ACTION_DELETE_MATCH, None
        )
        ida_kernwin.attach_action_to_popup(
            widget, popup_handle, ACTION_CONFIRM_MATCH, None
        )

    # --- Static Methods for easy access ---
    @staticmethod
    def show():
        """Creates and shows the chooser"""
        chooser = MatchedFunctionsChooser()
        chooser.Show()  # Show modally
        # chooser.choose() # Use this for non-modal like C++ (might require different handling)

    @staticmethod
    def refresh_if_open():
        """Refreshes the chooser if it's currently open."""
        widget = ida_kernwin.find_widget(f"Matched Functions ({PLUGIN_NAME})")
        if widget:
            chooser = ida_kernwin.get_chooser_obj(
                widget
            )  # Attempt to get chooser object
            if chooser and isinstance(chooser, MatchedFunctionsChooser):
                chooser.OnRefresh(chooser.GetSelectionIndex())
            else:
                # Might be a native widget, try refreshing directly (if applicable)
                ida_kernwin.refresh_chooser(f"Matched Functions ({PLUGIN_NAME})")
        else:
            log.debug("MatchedFunctionsChooser not open, skipping refresh.")


# --- Other Choosers (Placeholders) ---
class UnmatchedFunctionsChooserPrimary(ida_kernwin.Choose):
    """Chooser class to display unmatched functions in the primary binary."""

    def __init__(self, title=f"Unmatched Primary ({PLUGIN_NAME})"):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                ["Name", 40 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["BB Count", 10 | ida_kernwin.Choose.CHCOL_DEC],
                ["Inst Count", 10 | ida_kernwin.Choose.CHCOL_DEC],
                ["Edge Count", 10 | ida_kernwin.Choose.CHCOL_DEC],
            ],
            flags=ida_kernwin.Choose.CH_MULTI,
        )
        self.items = []
        self.icon = -1
        self.populate_items()

    def populate_items(self):
        global bindiff_results
        self.items = []
        if not bindiff_results:
            log.warning("Cannot populate UnmatchedPrimaryChooser: Results not loaded.")
            return

        try:
            # python-bindiff provides primary_unmatched_function()
            # It returns a list of FunctionBinExport objects
            for func in bindiff_results.primary_unmatched_function():
                addr_str = f"{func.addr:#x}"
                name = func.name if hasattr(func, "name") else "N/A"

                # Calculate counts
                bb_count = (
                    len(func.basic_blocks) if hasattr(func, "basic_blocks") else -1
                )
                edge_count = (
                    sum(
                        len(bb.successors)
                        for bb in func.basic_blocks
                        if hasattr(bb, "successors")
                    )
                    if bb_count != -1
                    else -1
                )
                inst_count = (
                    sum(
                        len(bb.instructions)
                        for bb in func.basic_blocks
                        if hasattr(bb, "instructions")
                    )
                    if bb_count != -1
                    else -1
                )

                bb_count_str = str(bb_count) if bb_count != -1 else "-"
                inst_count_str = str(inst_count) if inst_count != -1 else "-"
                edge_count_str = str(edge_count) if edge_count != -1 else "-"

                self.items.append(
                    [
                        addr_str,
                        name,
                        bb_count_str,
                        inst_count_str,
                        edge_count_str,
                        func,  # Store original object
                    ]
                )
            log.info(f"Populated UnmatchedPrimaryChooser with {len(self.items)} items.")
        except AttributeError as e:
            log.error(
                f"Attribute error accessing unmatched primary data: {e}. Check library API.",
                exc_info=True,
            )
            ida_kernwin.warning(f"Error accessing BinDiff data attributes: {e}")
        except Exception as e:
            log.error(f"Failed to populate UnmatchedPrimaryChooser: {e}", exc_info=True)
            ida_kernwin.warning(f"Failed to populate chooser: {e}")

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n][:-1]

    def OnSelectLine(self, n):
        if not self.items or n >= len(self.items):
            return
        func = self.items[n][-1]
        log.info(f"Selected unmatched primary: {func.name} ({func.addr:#x})")
        ida_kernwin.jumpto(func.addr)

    def OnDeleteLine(self, n):
        # Deleting an unmatched function doesn't make sense in this context
        log.info("Delete action not applicable to unmatched functions.")
        return n

    def OnRefresh(self, n):
        self.populate_items()
        return n

    def OnClose(self):
        log.info("UnmatchedPrimaryChooser closed.")

    def OnGetPopupMenu(self, widget, popup_handle):
        """Add context menu items."""
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "-")  # Separator
        plugin_instance = ida_idaapi.get_plugin_instance(BinDiffPlugin)
        if plugin_instance and hasattr(plugin_instance, "_add_match_handler_type"):
            action_desc_add = ida_kernwin.action_desc_t(
                None,
                "Add ~M~atch...",
                plugin_instance._add_match_handler_type(self, is_primary_chooser=True),
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup_handle,
                ACTION_ADD_MATCH,
                None,
                action_desc=action_desc_add,
            )


class UnmatchedFunctionsChooserSecondary(ida_kernwin.Choose):
    """Chooser class to display unmatched functions in the secondary binary."""

    def __init__(self, title=f"Unmatched Secondary ({PLUGIN_NAME})"):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                ["Name", 40 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["BB Count", 10 | ida_kernwin.Choose.CHCOL_DEC],
                ["Inst Count", 10 | ida_kernwin.Choose.CHCOL_DEC],
                ["Edge Count", 10 | ida_kernwin.Choose.CHCOL_DEC],
            ],
            flags=ida_kernwin.Choose.CH_MULTI,
        )
        self.items = []
        self.icon = -1
        self.populate_items()

    def populate_items(self):
        global bindiff_results
        self.items = []
        if not bindiff_results:
            log.warning(
                "Cannot populate UnmatchedSecondaryChooser: Results not loaded."
            )
            return

        try:
            # python-bindiff provides secondary_unmatched_function()
            for func in bindiff_results.secondary_unmatched_function():
                addr_str = f"{func.addr:#x}"
                name = func.name if hasattr(func, "name") else "N/A"

                # Calculate counts
                bb_count = (
                    len(func.basic_blocks) if hasattr(func, "basic_blocks") else -1
                )
                edge_count = (
                    sum(
                        len(bb.successors)
                        for bb in func.basic_blocks
                        if hasattr(bb, "successors")
                    )
                    if bb_count != -1
                    else -1
                )
                inst_count = (
                    sum(
                        len(bb.instructions)
                        for bb in func.basic_blocks
                        if hasattr(bb, "instructions")
                    )
                    if bb_count != -1
                    else -1
                )

                bb_count_str = str(bb_count) if bb_count != -1 else "-"
                inst_count_str = str(inst_count) if inst_count != -1 else "-"
                edge_count_str = str(edge_count) if edge_count != -1 else "-"

                self.items.append(
                    [
                        addr_str,
                        name,
                        bb_count_str,
                        inst_count_str,
                        edge_count_str,
                        func,  # Store original object
                    ]
                )
            log.info(
                f"Populated UnmatchedSecondaryChooser with {len(self.items)} items."
            )
        except AttributeError as e:
            log.error(
                f"Attribute error accessing unmatched secondary data: {e}. Check library API.",
                exc_info=True,
            )
            ida_kernwin.warning(f"Error accessing BinDiff data attributes: {e}")
        except Exception as e:
            log.error(
                f"Failed to populate UnmatchedSecondaryChooser: {e}", exc_info=True
            )
            ida_kernwin.warning(f"Failed to populate chooser: {e}")

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n][:-1]

    def OnSelectLine(self, n):
        # Double-clicking an unmatched secondary function - what should it do?
        # Jumping doesn't make sense as it's not in the current IDB.
        # Maybe copy address? Or just log?
        if not self.items or n >= len(self.items):
            return
        func = self.items[n][-1]
        log.info(f"Selected unmatched secondary: {func.name} ({func.addr:#x})")
        # Potential actions: Copy address to clipboard
        # ida_kernwin.str2clip(f"{func.addr:#x}")

    def OnDeleteLine(self, n):
        log.info("Delete action not applicable to unmatched functions.")
        return n

    def OnRefresh(self, n):
        self.populate_items()
        return n

    def OnClose(self):
        log.info("UnmatchedSecondaryChooser closed.")

    def OnGetPopupMenu(self, widget, popup_handle):
        """Add context menu items."""
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "-")  # Separator
        plugin_instance = ida_idaapi.get_plugin_instance(BinDiffPlugin)
        if plugin_instance and hasattr(plugin_instance, "_add_match_handler_type"):
            action_desc_add = ida_kernwin.action_desc_t(
                None,
                "Add ~M~atch...",
                plugin_instance._add_match_handler_type(self, is_primary_chooser=False),
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup_handle,
                ACTION_ADD_MATCH,
                None,
                action_desc=action_desc_add,
            )


class StatisticsChooser(ida_kernwin.Choose):
    """Chooser class to display BinDiff statistics."""

    def __init__(self, title=f"Statistics ({PLUGIN_NAME})"):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Name", 40 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Value", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
        )  # No multi-select needed
        self.items = []
        self.icon = -1
        self.populate_items()

    def populate_items(self):
        global bindiff_results
        self.items = []
        if not bindiff_results:
            log.warning("Cannot populate StatisticsChooser: Results not loaded.")
            return

        try:
            # --- Overall Stats ---
            self.items.append(["Similarity", f"{bindiff_results.similarity:.4f}", None])
            self.items.append(["Confidence", f"{bindiff_results.confidence:.4f}", None])
            self.items.append(["-" * 20, "-" * 10, None])  # Separator

            # --- Primary Stats ---
            # Use attributes from the `File` object within BindiffFile
            try:
                # Access the underlying BindiffFile - this might need adjustment if the attribute name changes
                # Assuming it's stored in _primary_diff (or similar internal var)
                diff_file = bindiff_results._primary_diff
                prog1_file = diff_file.primary_file_  # Get the File object

                self.items.append(
                    [
                        "Primary Functions",
                        (
                            str(prog1_file.functions_)
                            if hasattr(prog1_file, "functions_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Primary Lib Functions",
                        (
                            str(prog1_file.libfunctions_)
                            if hasattr(prog1_file, "libfunctions_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Primary Basic Blocks",
                        (
                            str(prog1_file.basicblocks_)
                            if hasattr(prog1_file, "basicblocks_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Primary Instructions",
                        (
                            str(prog1_file.instructions_)
                            if hasattr(prog1_file, "instructions_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Primary Edges",
                        (
                            str(prog1_file.edges_)
                            if hasattr(prog1_file, "edges_")
                            else "?"
                        ),
                        None,
                    ]
                )
            except AttributeError:
                log.warning(
                    "Could not access primary file stats from BindiffFile object. Attributes might be missing or renamed."
                )
                self.items.append(["Primary Functions", "?", None])
                self.items.append(["Primary Basic Blocks", "?", None])
                self.items.append(["Primary Instructions", "?", None])
                self.items.append(["Primary Edges", "?", None])

            self.items.append(["-" * 20, "-" * 10, None])  # Separator

            # --- Secondary Stats ---
            try:
                diff_file = (
                    bindiff_results._primary_diff
                )  # Use same BindiffFile obj for secondary info
                prog2_file = diff_file.secondary_file_

                self.items.append(
                    [
                        "Secondary Functions",
                        (
                            str(prog2_file.functions_)
                            if hasattr(prog2_file, "functions_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Secondary Lib Functions",
                        (
                            str(prog2_file.libfunctions_)
                            if hasattr(prog2_file, "libfunctions_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Secondary Basic Blocks",
                        (
                            str(prog2_file.basicblocks_)
                            if hasattr(prog2_file, "basicblocks_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Secondary Instructions",
                        (
                            str(prog2_file.instructions_)
                            if hasattr(prog2_file, "instructions_")
                            else "?"
                        ),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Secondary Edges",
                        (
                            str(prog2_file.edges_)
                            if hasattr(prog2_file, "edges_")
                            else "?"
                        ),
                        None,
                    ]
                )
            except AttributeError:
                log.warning(
                    "Could not access secondary file stats from BindiffFile object. Attributes might be missing or renamed."
                )
                self.items.append(["Secondary Functions", "?", None])
                self.items.append(["Secondary Basic Blocks", "?", None])
                self.items.append(["Secondary Instructions", "?", None])
                self.items.append(["Secondary Edges", "?", None])

            self.items.append(["-" * 20, "-" * 10, None])  # Separator

            # --- Match Stats ---
            try:
                diff_file = bindiff_results._primary_diff  # Use same BindiffFile obj
                num_matched_funcs = len(diff_file.function_matches_)
                num_unmatched_primary = diff_file.unmatched_primary_count_
                num_unmatched_secondary = diff_file.unmatched_secondary_count_

                self.items.append(
                    [
                        "Matched Functions",
                        str(num_matched_funcs),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Unmatched Primary",
                        str(num_unmatched_primary),
                        None,
                    ]
                )
                self.items.append(
                    [
                        "Unmatched Secondary",
                        str(num_unmatched_secondary),
                        None,
                    ]
                )
            except AttributeError:
                log.warning(
                    "Could not access match stats from BindiffFile object. Attributes might be missing or renamed."
                )
                self.items.append(["Matched Functions", "?", None])
                self.items.append(["Unmatched Primary", "?", None])
                self.items.append(["Unmatched Secondary", "?", None])

            # TODO: Add matched BB/Instruction counts if available

            log.info(f"Populated StatisticsChooser with {len(self.items)} items.")
        except AttributeError as e:
            log.error(
                f"Attribute error accessing statistics data: {e}. Check library API.",
                exc_info=True,
            )
            ida_kernwin.warning(f"Error accessing BinDiff data attributes: {e}")
        except Exception as e:
            log.error(f"Failed to populate StatisticsChooser: {e}", exc_info=True)
            ida_kernwin.warning(f"Failed to populate chooser: {e}")

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        # Return only the displayable parts
        return self.items[n][:2]

    def OnSelectLine(self, n):
        # Double-clicking a statistic doesn't do anything specific
        log.debug(f"Selected statistic: {self.items[n][0]}")
        pass

    def OnDeleteLine(self, n):
        # Not applicable
        return n

    def OnRefresh(self, n):
        self.populate_items()
        return n

    def OnClose(self):
        log.info("StatisticsChooser closed.")

    @staticmethod
    def show():
        chooser = StatisticsChooser()
        chooser.Show()

    @staticmethod
    def refresh_if_open():
        widget = ida_kernwin.find_widget(f"Statistics ({PLUGIN_NAME})")
        if widget:
            chooser = ida_kernwin.get_chooser_obj(widget)
            if chooser:
                chooser.OnRefresh(chooser.GetSelectionIndex())
            else:
                ida_kernwin.refresh_chooser(f"Statistics ({PLUGIN_NAME})")
        else:
            log.debug("StatisticsChooser not open, skipping refresh.")


# --- Helper Functions ---


def prompt_save_if_modified():
    """Checks if results are modified and prompts user to save. Returns False if user cancels."""
    global bindiff_results, bindiff_results_modified
    if bindiff_results and bindiff_results_modified:
        res = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "HIDECANCEL\nBinDiff results have been modified. Save them first?",
        )
        if res == ida_kernwin.ASKBTN_YES:
            success = save_bindiff_results()  # Call the actual save function
            return success  # Only proceed if save was successful (or not cancelled)
        elif res == ida_kernwin.ASKBTN_CANCEL:
            return False  # User cancelled the operation
        # else (NO): Continue without saving
    return True  # OK to proceed (not modified or user chose not to save)


def save_bindiff_results():
    """Prompts for save path and saves the current BinDiff results."""
    global bindiff_results, bindiff_results_modified
    if not bindiff_results:
        ida_kernwin.warning("No BinDiff results to save.")
        return False

    # Get the original file path if available (from the underlying BindiffFile)
    original_diff_path = None
    try:
        if hasattr(bindiff_results, "_primary_diff") and bindiff_results._primary_diff:
            db_file: bindiff.file.BindiffFile = bindiff_results._primary_diff
            if hasattr(db_file, "filename_"):
                original_diff_path = db_file.filename_
    except Exception as e:
        log.warning(f"Could not retrieve original diff file path: {e}")

    # If results are modified, we cannot save them reliably yet.
    if bindiff_results_modified:
        log.error("Saving modified BinDiff results is not currently supported.")
        ida_kernwin.warning(
            "Results have been modified (e.g., manual matches added).\n"
            "Saving modifications is not yet supported by this plugin.\n"
            "Please save before making modifications or use the official BinDiff UI."
        )
        return False

    # If results are not modified, but we don't have the original path (e.g., diff never saved),
    # we also cannot save.
    if not original_diff_path:
        log.error("Cannot save results: Original .BinDiff file path is unknown.")
        ida_kernwin.warning(
            "Cannot save results as the original file path is unknown (was the diff ever saved?)."
        )
        return False

    # Suggest a filename based on the original path
    default_filename = os.path.basename(original_diff_path)

    save_path = ida_kernwin.ask_file(
        True, "*.BinDiff", f"Save BinDiff Results As ({default_filename})"
    )
    if not save_path:
        log.info("Save cancelled by user.")
        return False  # Indicate cancellation/failure

    # Since results are not modified, we just copy the original file.
    log.info(
        f"Saving (copying) unmodified BinDiff results from {original_diff_path} to: {save_path}"
    )
    ida_kernwin.show_wait_box("Saving BinDiff Results (Copying Original)...")
    try:
        shutil.copy2(original_diff_path, save_path)  # copy2 preserves metadata
        log.info("Unmodified results copied successfully.")
        # Reset modified flag (although it should already be False here)
        bindiff_results_modified = False
        ida_kernwin.hide_wait_box()
        return True
    except Exception as e:
        log.error(f"Failed to copy original results file: {e}", exc_info=True)
        ida_kernwin.warning(f"Error saving results (copying file):\n{e}")
        return False
    finally:
        if ida_pro.is_idaq():
            ida_kernwin.hide_wait_box()


def diff_database():
    """Prompts user for secondary, output, runs BinDiff, and loads results."""
    global bindiff_results

    if not PYTHON_BINDIFF_AVAILABLE:
        ida_kernwin.warning("BinDiff dependencies not available.")
        return False

    # Check for BinExport (rudimentary check for now)
    try:
        import binexport  # Assumes python-binexport is installed if python-bindiff is
    except ImportError:
        ida_kernwin.warning(
            "python-binexport library not found. Diffing requires BinExport."
        )
        return False

    primary_path = ida_nalt.get_input_file_path()
    if not primary_path:
        ida_kernwin.warning("No IDB open.")
        return False

    if not prompt_save_if_modified():
        return False

    # Ask for secondary binary
    secondary_path = ida_kernwin.ask_file(False, "*.*", "Select Secondary Binary/IDB")
    if not secondary_path or not os.path.exists(secondary_path):
        log.info("Diff cancelled or secondary file invalid.")
        return False

    # Ask for output .BinDiff file path
    default_diff_name = f"{os.path.splitext(os.path.basename(primary_path))[0]}_vs_{os.path.splitext(os.path.basename(secondary_path))[0]}.BinDiff"
    diff_output_path = ida_kernwin.ask_file(
        True, "*.BinDiff", f"Save BinDiff Results As ({default_diff_name})"
    )
    if not diff_output_path:
        log.info("Diff cancelled, no output path specified.")
        return False

    log.info(f"Starting diff: {primary_path} vs {secondary_path} -> {diff_output_path}")
    ida_kernwin.show_wait_box(
        f"Running BinDiff...\nPrimary: {os.path.basename(primary_path)}\nSecondary: {os.path.basename(secondary_path)}"
    )
    try:
        # Use python-bindiff to perform export and diff
        # This requires BinExport (via python-binexport) and the BinDiff differ executable
        # Ensure differ is in PATH or BINDIFF_PATH env var is set
        new_results = bindiff.BinDiff.from_binary_files(
            primary_path, secondary_path, diff_output_path, override=True
        )

        if new_results:
            bindiff_results = new_results
            log.info("Diff completed successfully.")
            # Update modification state? Assume freshly diffed results aren't modified yet.
            refresh_all_choosers()
            # Maybe open Matched Functions chooser automatically?
            # MatchedFunctionsChooser.show()
            return True
        else:
            # from_binary_files might return None on failure
            log.error("BinDiff.from_binary_files returned None. Diff failed.")
            ida_kernwin.warning("Diffing process failed. Check logs.")
            bindiff_results = None  # Ensure results are cleared
            refresh_all_choosers()
            return False

    except bindiff.types.BindiffNotFound as e:
        log.error(f"BinDiff differ executable not found: {e}")
        ida_kernwin.warning(
            f"BinDiff differ executable not found. Please check installation and PATH/BINDIFF_PATH.\n{e}"
        )
        return False
    except Exception as e:
        # Catch potential errors from binexport or the differ subprocess
        log.error(f"Diffing failed: {e}", exc_info=True)
        ida_kernwin.warning(f"Error during diffing process:\n{e}")
        # Make sure results are cleared if diff fails midway
        bindiff_results = None
        refresh_all_choosers()
        return False
    finally:
        if ida_pro.is_idaq():
            ida_kernwin.hide_wait_box()


def refresh_all_choosers():
    """Calls the refresh_if_open static method for all defined choosers."""
    log.debug("Refreshing all BinDiff choosers...")
    MatchedFunctionsChooser.refresh_if_open()
    UnmatchedFunctionsChooserPrimary.refresh_if_open()
    UnmatchedFunctionsChooserSecondary.refresh_if_open()
    StatisticsChooser.refresh_if_open()


def show_visual_diff(func1, func2):
    """Displays the control flow graphs of two matched functions side-by-side."""
    global bindiff_results
    if not bindiff_results:
        log.error("Cannot perform visual diff: Results not loaded.")
        return

    log.info(
        f"Preparing visual diff for {func1.addr:#x} ({func1.name}) and {func2.addr:#x} ({func2.name})"
    )

    # 1. Get Basic Block Matches
    bb_matches = {}
    primary_matched_bbs = set()
    secondary_matched_bbs = set()
    try:
        for bb1, bb2, bb_match_obj in bindiff_results.iter_basicblock_matches(
            func1, func2
        ):
            bb_matches[bb1.addr] = bb2.addr
            primary_matched_bbs.add(bb1.addr)
            secondary_matched_bbs.add(bb2.addr)
        log.debug(f"Found {len(bb_matches)} basic block matches.")
    except Exception as e:
        log.error(f"Failed to get basic block matches: {e}", exc_info=True)
        # Continue without bb match info?

    # 2. Build Graph Data (Nodes and Edges) for Primary
    primary_nodes = {}
    primary_edges = []
    primary_node_id_to_addr = {}
    primary_addr_to_node_id = {}
    # Use dicts to map IDA node IDs <-> our internal 0-based IDs
    primary_ida_node_ids = {}
    primary_internal_to_ida_id = {}
    internal_id_counter = 0

    ida_func1 = ida_funcs.get_func(func1.addr)
    if not ida_func1:
        log.error(f"Could not get IDA function object for primary at {func1.addr:#x}")
        return
    fc1 = ida_gdl.FlowChart(ida_func1)

    # First pass: Create nodes map
    for i in range(fc1.size):
        bb = fc1[i]
        internal_id = internal_id_counter
        internal_id_counter += 1
        primary_nodes[internal_id] = bb
        primary_node_id_to_addr[internal_id] = bb.start_ea
        primary_addr_to_node_id[bb.start_ea] = internal_id

    # Second pass: Create edges using internal IDs
    for internal_id, bb in primary_nodes.items():
        src_node_id = internal_id  # Our internal ID
        for succ_bb in bb.succs():
            if succ_bb.start_ea in primary_addr_to_node_id:
                dst_node_id = primary_addr_to_node_id[succ_bb.start_ea]  # Internal ID
                primary_edges.append((src_node_id, dst_node_id))
            else:
                log.warning(
                    f"Primary edge target {succ_bb.start_ea:#x} not found in function nodes."
                )

    # 3. Build Graph Data for Secondary
    secondary_nodes = {}
    secondary_edges = []
    secondary_node_id_to_addr = {}
    secondary_addr_to_node_id = {}
    secondary_ida_node_ids = {}
    secondary_internal_to_ida_id = {}
    internal_id_counter = 0

    if not hasattr(func2, "basic_blocks"):
        log.error(
            "Secondary function object lacks 'basic_blocks' attribute. Cannot build graph."
        )
        return

    # First pass: Create nodes map
    for bb in func2.basic_blocks:
        internal_id = internal_id_counter
        internal_id_counter += 1
        secondary_nodes[internal_id] = bb
        secondary_node_id_to_addr[internal_id] = bb.addr
        secondary_addr_to_node_id[bb.addr] = internal_id

    # Second pass: Create edges using internal IDs
    for internal_id, bb in secondary_nodes.items():
        src_node_id = internal_id  # Our internal ID
        if hasattr(bb, "successors"):
            for succ_addr in bb.successors:
                if succ_addr in secondary_addr_to_node_id:
                    dst_node_id = secondary_addr_to_node_id[succ_addr]  # Internal ID
                    secondary_edges.append((src_node_id, dst_node_id))
                else:
                    log.warning(
                        f"Secondary edge target {succ_addr:#x} not found in function nodes."
                    )
        else:
            log.warning(f"Secondary BB {bb.addr:#x} lacks 'successors' attribute.")

    # 4. Create GraphViewers
    gv_primary = ida_graph.GraphViewer(f"Primary: {func1.name} ({func1.addr:#x})", True)
    gv_secondary = ida_graph.GraphViewer(
        f"Secondary: {func2.name} ({func2.addr:#x})", True
    )

    # 5. Populate GraphViewers & Store IDA Node IDs
    # Primary Graph
    for internal_id, bb in sorted(primary_nodes.items()):  # Add in consistent order
        node_text = f"BB @ {bb.start_ea:#x}\n"
        curr_ea = bb.start_ea
        while curr_ea < bb.end_ea:
            # Limit number of lines to avoid excessive text
            MAX_LINES = 15
            lines = node_text.count("\n")
            if lines > MAX_LINES:
                if not node_text.endswith("...\n"):
                    node_text += "..."
                break
            node_text += ida_lines.generate_disasm_line(curr_ea, 0) + "\n"
            curr_ea = ida_nalt.next_head(curr_ea, bb.end_ea)

        ida_node_id = gv_primary.AddNode(node_text.strip())
        primary_ida_node_ids[internal_id] = ida_node_id
        primary_internal_to_ida_id[ida_node_id] = internal_id

    for src_internal_id, dst_internal_id in primary_edges:
        if (
            src_internal_id in primary_ida_node_ids
            and dst_internal_id in primary_ida_node_ids
        ):
            src_ida_id = primary_ida_node_ids[src_internal_id]
            dst_ida_id = primary_ida_node_ids[dst_internal_id]
            gv_primary.AddEdge(src_ida_id, dst_ida_id)
        else:
            log.warning(
                f"Skipping primary edge due to missing node IDs: {src_internal_id} -> {dst_internal_id}"
            )

    # Secondary Graph
    for internal_id, bb in sorted(secondary_nodes.items()):  # Add in consistent order
        node_text = f"BB @ {bb.addr:#x}\n"
        if hasattr(bb, "instructions"):
            inst_count = 0
            MAX_LINES = 15
            for inst in bb.instructions:
                inst_count += 1
                if inst_count > MAX_LINES:
                    if not node_text.endswith("...\n"):
                        node_text += "..."
                    break
                node_text += str(inst) + "\n"
        else:
            node_text += "(Instructions not available)"

        ida_node_id = gv_secondary.AddNode(node_text.strip())
        secondary_ida_node_ids[internal_id] = ida_node_id
        secondary_internal_to_ida_id[ida_node_id] = internal_id

    for src_internal_id, dst_internal_id in secondary_edges:
        if (
            src_internal_id in secondary_ida_node_ids
            and dst_internal_id in secondary_ida_node_ids
        ):
            src_ida_id = secondary_ida_node_ids[src_internal_id]
            dst_ida_id = secondary_ida_node_ids[dst_internal_id]
            gv_secondary.AddEdge(src_ida_id, dst_ida_id)
        else:
            log.warning(
                f"Skipping secondary edge due to missing node IDs: {src_internal_id} -> {dst_internal_id}"
            )

    # 6. Color Nodes using SetNodeInfo
    COLOR_MATCH = 0xAAFFAA  # Lighter Green
    COLOR_PRIMARY_UNMATCHED = 0xFFCCCC  # Lighter Red
    COLOR_SECONDARY_UNMATCHED = 0xCCCCFF  # Lighter Blue
    COLOR_DEFAULT = 0xFFFFFF  # White

    # Color Primary Graph
    for internal_id, ida_node_id in primary_ida_node_ids.items():
        addr = primary_node_id_to_addr[internal_id]
        color = COLOR_DEFAULT
        if addr in bb_matches:
            color = COLOR_MATCH
        else:
            color = COLOR_PRIMARY_UNMATCHED

        # Use SetNodeInfo to set background color
        node_info = ida_graph.node_info_t()
        node_info.bg_color = color
        gv_primary.SetNodeInfo(ida_node_id, node_info, ida_graph.NIF_BG_COLOR)

    # Color Secondary Graph
    for internal_id, ida_node_id in secondary_ida_node_ids.items():
        addr = secondary_node_id_to_addr[internal_id]
        color = COLOR_DEFAULT
        if (
            addr in secondary_matched_bbs
        ):  # Check if this secondary BB address was matched
            color = COLOR_MATCH
        else:
            color = COLOR_SECONDARY_UNMATCHED

        node_info = ida_graph.node_info_t()
        node_info.bg_color = color
        gv_secondary.SetNodeInfo(ida_node_id, node_info, ida_graph.NIF_BG_COLOR)

    # 7. Show Graphs
    gv_primary.Show()
    gv_secondary.Show()
    log.info("Displayed visual diff graphs.")


def port_comments_symbols(
    use_selection, selection_indices, min_similarity=0.0, min_confidence=0.0
):
    """Ports function names (and potentially comments if available) from secondary to primary IDB based on matches."""
    global bindiff_results, bindiff_results_modified
    if not bindiff_results:
        log.error("Cannot port comments/symbols: Results not loaded.")
        return False

    log.info(
        f"Starting porting (Selection: {use_selection}, Indices: {selection_indices}, Min Sim: {min_similarity}, Min Conf: {min_confidence})"
    )
    ida_kernwin.show_wait_box("Porting Names and Symbols...")
    ported_name_count = 0
    ported_comment_count = 0
    skipped_count = 0
    comments_available = False  # Flag to check if comments are available
    try:
        matches_to_process = []
        if use_selection:
            # Need to get the correct chooser instance based on the current widget context
            widget = ida_kernwin.get_current_widget()
            chooser_title = ida_kernwin.get_widget_title(widget)
            chooser = None
            if chooser_title == f"Matched Functions ({PLUGIN_NAME})":
                chooser = ida_kernwin.get_chooser_obj(widget)

            if (
                not chooser
                or not hasattr(chooser, "items")
                or not isinstance(chooser, MatchedFunctionsChooser)
            ):
                log.error(
                    "Could not get MatchedFunctionsChooser items for selection-based porting."
                )
                ida_kernwin.warning(
                    "Porting selection only available from Matched Functions chooser."
                )
                return False
            for idx in selection_indices:
                if 0 <= idx < len(chooser.items):
                    matches_to_process.append(
                        chooser.items[idx][-1]
                    )  # Get (func1, func2, match_obj)
        else:
            # Port all matches
            matches_to_process = list(bindiff_results.iter_function_matches())

        if not matches_to_process:
            log.warning("No matches found to process for porting.")
            return False

        # Check if comment attribute exists on the first secondary function (assume consistent API)
        _, func2_sample, _ = matches_to_process[0]
        if hasattr(func2_sample, "comment"):  # Check for a 'comment' attribute
            comments_available = True
            log.info("Secondary function comments appear to be available for porting.")
        else:
            log.warning(
                "Secondary function comments attribute not found. Comments will not be ported."
            )

        # --- Filter Matches --- #
        filtered_matches = []
        if use_selection:
            # ... (Get chooser and selected matches) ...
            if not matches_to_process:  # Add check here too
                return False  # Already logged error in previous block
            # Selection doesn't use similarity/confidence filter (user explicitly selected)
            filtered_matches = matches_to_process
        else:
            # Apply similarity/confidence filters
            for func1, func2, match_obj in bindiff_results.iter_function_matches():
                if (
                    match_obj.similarity >= min_similarity
                    and match_obj.confidence >= min_confidence
                ):
                    filtered_matches.append((func1, func2, match_obj))

        if not filtered_matches:
            log.warning("No matches passed the filter criteria.")
            ida_kernwin.info(
                "No matches passed the filter criteria for porting."
            )  # User-facing info
            return False  # Return False, but not necessarily an error

        # Process the filtered matches
        for func1, func2, match_obj in filtered_matches:
            try:
                name_ported = False
                comment_ported = False

                # --- Port Function Name ---
                if hasattr(func2, "name") and func2.name and func2.name != func1.name:
                    new_name = func2.name
                    log.debug(
                        f"Attempting to rename {func1.addr:#x} ('{func1.name}') to '{new_name}'"
                    )
                    if ida_name.set_name(
                        func1.addr, new_name, ida_name.SN_CHECK | ida_name.SN_NOWARN
                    ):
                        log.debug(f"  Successfully renamed {func1.addr:#x}")
                        ported_name_count += 1
                        name_ported = True
                    else:
                        log.warning(
                            f"  Failed to rename {func1.addr:#x} to '{new_name}' (maybe invalid chars or duplicate?)"
                        )
                # --- Port Function Comment ---
                if comments_available:
                    secondary_comment = func2.comment  # Access the comment attribute
                    if secondary_comment:
                        ida_func = ida_funcs.get_func(func1.addr)
                        if ida_func:
                            existing_comment = ida_funcs.get_func_cmt(
                                ida_func, True
                            )  # Repeatable comment
                            if existing_comment != secondary_comment:
                                log.debug(
                                    f"Setting repeatable comment for {func1.addr:#x}"
                                )
                                if ida_funcs.set_func_cmt(
                                    ida_func, secondary_comment, True
                                ):
                                    ported_comment_count += 1
                                    comment_ported = True
                                else:
                                    log.warning(
                                        f"  Failed to set function comment for {func1.addr:#x}"
                                    )
                        else:
                            log.warning(
                                f"Could not get IDA function object for {func1.addr:#x} to set comment."
                            )

                if not name_ported and not comment_ported:
                    skipped_count += 1

                # TODO: Port Basic Block comments? Instruction comments?
                # Requires iterating bb_matches and inst_matches and getting comments from secondary.

            except Exception as inner_e:
                log.error(
                    f"Error porting data for match {func1.addr:#x} <-> {func2.addr:#x}: {inner_e}",
                    exc_info=True,
                )
                skipped_count += 1

        log.info(
            f"Finished porting. Names Ported: {ported_name_count}, Comments Ported: {ported_comment_count}, Skipped/Failed: {skipped_count}"
        )
        if ported_name_count > 0 or ported_comment_count > 0:
            bindiff_results_modified = (
                True  # Consider IDB changes (names/comments) as needing potential save?
            )
            # Refresh views to show changes
            # No standard way to refresh disassembly, but choosers can be refreshed.
            refresh_all_choosers()  # Refresh choosers in case names changed
        return True

    except Exception as e:
        log.error(f"Failed to port comments/symbols: {e}", exc_info=True)
        ida_kernwin.warning(f"Error during comment/symbol porting:\\n{e}")
        return False
    finally:
        if ida_pro.is_idaq():
            ida_kernwin.hide_wait_box()


# --- Hooks ---
class BinDiffIDPHooks(ida_idp.IDP_Hooks):
    def savebase(self, *args):
        """Called when the database is being saved."""
        log.debug("IDP_Hooks.savebase triggered")
        # Prompt user to save BinDiff results if they are modified
        if not prompt_save_if_modified():
            log.warning(
                "User cancelled BinDiff save during IDB save. Aborting IDB save?"
            )
            # Returning -1 might signal IDA to cancel the save, but behavior is not guaranteed.
            return -1
        return 0  # Indicate success

    # TODO: Add other relevant hooks, e.g.:
    # closebase: Called before the database is closed. Could prompt save here too.
    # term: Called when IDA is terminating.


# --- Plugin Entry Point ---


def PLUGIN_ENTRY():
    return BinDiffPlugin()
