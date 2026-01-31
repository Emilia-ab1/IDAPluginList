import idaapi
from PyQt5 import QtWidgets

def PLUGIN_ENTRY():
    return IdaCluPlugin()

class IdaCluPlugin(idaapi.plugin_t):

    flags = 0
    comment = "Function Clusterization Tool"
    help = "Edit->Plugin->FindFunc or Ctrl+Alt+O."
    wanted_name = "IdaClu"
    wanted_hotkey = "Ctrl+Alt+O"

    def init(self):
        idaapi.msg("IdaClu plugin loaded\n")
        return idaapi.PLUGIN_OK
 
    def run(self, arg):
        f = IdaCluForm()
        f.Show('IdaClu')
        return
 
    def term(self):
        pass

class IdaCluForm(idaapi.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(
            QtWidgets.QLabel("<font color=red>Hello World!</font>"))
        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass
