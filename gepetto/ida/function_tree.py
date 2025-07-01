import idautils
import idaapi
import ida_kernwin
import ida_hexrays

import functools
import gepetto.config
from gepetto.ida.handlers import rename_callback

try:
    from PyQt5 import QtWidgets, QtCore
except Exception:
    from PySide2 import QtWidgets, QtCore  # type: ignore


class FunctionTreeForm(ida_kernwin.PluginForm):
    """Dockable widget displaying a tree of functions called by a root function."""

    def __init__(self, start_ea: int):
        super().__init__()
        self.start_ea = start_ea
        self.tree = None
        self.parent = None

    # ------------------------------------------------------------------
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setExpandsOnDoubleClick(False)
        self.tree.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.tree.itemDoubleClicked.connect(self._on_double_click)
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._on_context_menu)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        self.parent.setLayout(layout)
        self._populate_tree()

    # ------------------------------------------------------------------
    def _populate_tree(self, expanded=None):
        """Build or rebuild the tree, restoring expansion state if provided."""
        self.tree.clear()
        root = self._build_tree(self.tree.invisibleRootItem(), self.start_ea, set())
        if root is not None:
            if expanded is None:
                root.setExpanded(True)
            if expanded:
                self._restore_expanded_items(root, expanded)

    # ------------------------------------------------------------------
    def _build_tree(self, parent, ea, visited):
        name = idaapi.get_func_name(ea)
        item = QtWidgets.QTreeWidgetItem(parent, [name])
        item.setData(0, QtCore.Qt.UserRole, ea)
        if ea in visited:
            return item
        visited.add(ea)
        for child_ea in self._get_called_functions(ea):
            self._build_tree(item, child_ea, visited)
        return item

    # ------------------------------------------------------------------
    def _collect_expanded_items(self, item=None, result=None):
        """Return a set of addresses for all expanded items."""
        if result is None:
            result = set()
        if item is None:
            item = self.tree.invisibleRootItem()
        ea = item.data(0, QtCore.Qt.UserRole)
        if item != self.tree.invisibleRootItem() and item.isExpanded() and ea is not None:
            result.add(ea)
        for i in range(item.childCount()):
            self._collect_expanded_items(item.child(i), result)
        return result

    # ------------------------------------------------------------------
    def _restore_expanded_items(self, item, expanded):
        ea = item.data(0, QtCore.Qt.UserRole)
        if ea in expanded:
            item.setExpanded(True)
        for i in range(item.childCount()):
            self._restore_expanded_items(item.child(i), expanded)

    # ------------------------------------------------------------------
    @staticmethod
    def _get_called_functions(ea):
        calls = set()
        for head in idautils.FuncItems(ea):
            if idaapi.is_call_insn(head):
                for ref in idautils.CodeRefsFrom(head, False):
                    func = idaapi.get_func(ref)
                    if func:
                        calls.add(func.start_ea)
        return calls

    # ------------------------------------------------------------------
    def _on_double_click(self, item, column):
        ea = item.data(0, QtCore.Qt.UserRole)
        if ea is not None:
            ida_kernwin.jumpto(ea)

    # ------------------------------------------------------------------
    def _on_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        menu = QtWidgets.QMenu(self.tree)
        act_collapse = menu.addAction("Collapse")
        act_uncollapse = menu.addAction("Uncollapse")
        act_collapse_all = menu.addAction("Collapse All")
        act_uncollapse_all = menu.addAction("Uncollapse All")
        menu.addSeparator()
        act_rename = menu.addAction("Rename variables")
        act_rename_children = menu.addAction("Rename variables With Children")
        action = menu.exec_(self.tree.viewport().mapToGlobal(pos))
        if action == act_rename or action == act_rename_children:
            expanded = self._collect_expanded_items()
            selected = self.tree.selectedItems()
            targets = selected if selected else [item]
            for sel in targets:
                self._rename_item(sel, recurse=action == act_rename_children)
            self._populate_tree(expanded)
        elif action == act_collapse:
            selected = self.tree.selectedItems()
            targets = selected if selected else [item]
            for sel in targets:
                sel.setExpanded(False)
        elif action == act_uncollapse:
            selected = self.tree.selectedItems()
            targets = selected if selected else [item]
            for sel in targets:
                sel.setExpanded(True)
        elif action == act_collapse_all:
            selected = self.tree.selectedItems()
            targets = selected if selected else [item]
            for sel in targets:
                self._collapse_recursively(sel)
        elif action == act_uncollapse_all:
            selected = self.tree.selectedItems()
            targets = selected if selected else [item]
            for sel in targets:
                self._uncollapse_recursively(sel)

    # ------------------------------------------------------------------
    def _rename_item(self, item, recurse: bool):
        ea = item.data(0, QtCore.Qt.UserRole)
        if ea is None:
            return
        try:
            decompiler_output = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure:
            print(gepetto.config._(
                "Failed to decompile function at {address:#x}, skipping.").format(
                address=ea))
        else:
            gepetto.config.model.query_model_async(
                gepetto.config._(
                    "Analyze the following C function:\n{decompiler_output}"\
                    "\nSuggest better variable names, reply with a JSON array where keys are the original"\
                    " names and values are the proposed names. Do not explain anything, only print the "\
                    "JSON dictionary.").format(decompiler_output=str(decompiler_output)),
                functools.partial(rename_callback, address=ea, view=None),
                additional_model_options={"response_format": {"type": "json_object"}},
            )
            print(gepetto.config._("Request to {model} sent...").format(
                model=str(gepetto.config.model)))
        if recurse:
            for i in range(item.childCount()):
                self._rename_item(item.child(i), True)

    # ------------------------------------------------------------------
    def _collapse_recursively(self, item):
        item.setExpanded(False)
        for i in range(item.childCount()):
            self._collapse_recursively(item.child(i))

    # ------------------------------------------------------------------
    def _uncollapse_recursively(self, item):
        item.setExpanded(True)
        for i in range(item.childCount()):
            self._uncollapse_recursively(item.child(i))

    # ------------------------------------------------------------------
    def Show(self, caption, options=0):
        return super().Show(caption, options)


class GenerateFunctionsTreeHandler(idaapi.action_handler_t):
    """Handler to create and display the functions tree form."""

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.form = None

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        self.form = FunctionTreeForm(ea)
        self.form.Show("Functions Tree", options=ida_kernwin.PluginForm.WOPN_DP_RIGHT)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

