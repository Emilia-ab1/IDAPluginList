from idaapi import PluginForm
from PySide import QtGui, QtCore
class	MyPluginFormClass(PluginForm):
	def OnCreate(self,form):
		self.parent = self.FormToPySideWidget(form)
		self.PopulateForm()
	def PopulateForm(self):
		layout = QtGui.QVBoxLayout()
		layout.addWidget(
			QtGui.QLabel("Hello from PySide"))
		layout.addWidget(
			QtGui.QLabel("Hello form IdaPython"))
		self.parent.setLayout(layout)
	def OnClose(self,form):
		pass
plg = MyPluginFormClass()
plg.Show("PySide Hello world")
