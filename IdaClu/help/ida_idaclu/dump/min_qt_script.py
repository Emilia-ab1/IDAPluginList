import idaapi
from PyQt5 import QtWidgets

class MyPluginForm(idaapi.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(
            QtWidgets.QLabel("<font color=red>Hello World!</font>"))
        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass

plg = MyPluginForm()
plg.Show("Qt Form")
