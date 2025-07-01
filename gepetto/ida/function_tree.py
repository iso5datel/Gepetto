import idautils
import idaapi
import ida_kernwin
import ida_hexrays

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
        self.tree.itemDoubleClicked.connect(self._on_double_click)
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._on_context_menu)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        self.parent.setLayout(layout)
        self._populate_tree()

    # ------------------------------------------------------------------
    def _populate_tree(self):
        self.tree.clear()
        self._build_tree(self.tree.invisibleRootItem(), self.start_ea, set())
        self.tree.expandAll()

    # ------------------------------------------------------------------
    def _build_tree(self, parent, ea, visited):
        name = idaapi.get_func_name(ea)
        item = QtWidgets.QTreeWidgetItem(parent, [name])
        item.setData(0, QtCore.Qt.UserRole, ea)
        if ea in visited:
            return
        visited.add(ea)
        for child_ea in self._get_called_functions(ea):
            self._build_tree(item, child_ea, visited)

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
        act_decompile = menu.addAction("Decompile")
        act_decompile_children = menu.addAction("Decompile With Children")
        action = menu.exec_(self.tree.viewport().mapToGlobal(pos))
        if action == act_decompile:
            self._decompile_item(item, recurse=False)
        elif action == act_decompile_children:
            self._decompile_item(item, recurse=True)
        self._populate_tree()

    # ------------------------------------------------------------------
    def _decompile_item(self, item, recurse: bool):
        ea = item.data(0, QtCore.Qt.UserRole)
        if ea is None:
            return
        try:
            ida_hexrays.decompile(ea)
        except Exception:
            pass
        if recurse:
            for i in range(item.childCount()):
                self._decompile_item(item.child(i), True)

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

