# This document contains the main dialog layout description,
# with all controls/widgets being imported.


from idaclu.qt_shims import (
    QAbstractItemView,
    QCursor,
    QFont,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QIcon,
    QLineEdit,
    QMetaObject,
    QPushButton,
    QRect,
    QScrollArea,
    QSize,
    QSizePolicy,
    QSpacerItem,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
    Qt
)
from idaclu.qt_utils import (
    ColorButton,
    FilterInputGroup,
    i18n,
    LabelTool,
    PaletteTool,
    ProgBar
)

class Ui_PluginDialog(object):
    def __init__(self, env_desc):
        self.env_desc = env_desc

    def setupUi(self, PluginDialog):

        # defines beg
        _Expanding = QSizePolicy.Expanding
        _Fixed = QSizePolicy.Fixed
        _Minimum = QSizePolicy.Minimum

        _AlignHCenter = Qt.AlignHCenter
        _AlignTop = Qt.AlignTop
        _CustomContextMenu = Qt.CustomContextMenu
        _Horizontal = Qt.Horizontal
        _PointingHandCursor = Qt.PointingHandCursor
        _ScrollBarAlwaysOff = Qt.ScrollBarAlwaysOff
        # defines end

        if not PluginDialog.objectName():
            PluginDialog.setObjectName(u"PluginDialog")
        PluginDialog.resize(1024, 600)

        icon = QIcon()
        icon.addFile(":/idaclu/icon_64.png", QSize(), QIcon.Normal, QIcon.Off)
        PluginDialog.setWindowIcon(icon)

        font = QFont()
        font.setBold(True)
        font.setWeight(75)

        self.PluginAdapter = QHBoxLayout(PluginDialog)
        self.PluginAdapter.setObjectName(u"PluginAdapter")

        self.MainSplitter = QSplitter()
        self.MainSplitter.setOrientation(_Horizontal)
        self.MainSplitter.setObjectName(u"MainSplitter")

        self.MainLayout = QHBoxLayout()
        self.MainLayout.setObjectName(u"MainLayout")

        self.SidebarFrame = QFrame(PluginDialog)

        self.ScriptsHeader = QPushButton(PluginDialog)
        self.ScriptsHeader.setObjectName(u"ScriptsHeader")
        self.ScriptsHeader.setMinimumSize(QSize(0, 30))
        self.ScriptsHeader.setFont(font)
        self.ScriptsHeader.setCursor(QCursor(_PointingHandCursor))
        self.ScriptsHeader.setProperty('class', 'head')

        self.ScriptsArea = QScrollArea(PluginDialog)
        self.ScriptsArea.setObjectName(u"ScriptsArea")
        self.ScriptsArea.setWidgetResizable(True)
        self.ScriptsArea.horizontalScrollBar().setEnabled(False)
        self.ScriptsArea.setHorizontalScrollBarPolicy(_ScrollBarAlwaysOff)

        self.ScriptsContents = QWidget()
        self.ScriptsContents.setObjectName(u"ScriptsContents")
        self.ScriptsContents.setGeometry(QRect(0, 0, 215, 233))

        self.ScriptsLayout = QVBoxLayout(self.ScriptsContents)
        self.ScriptsLayout.setSpacing(0)
        self.ScriptsLayout.setAlignment(_AlignTop)

        self.ScriptsArea.setWidget(self.ScriptsContents)

        self.ScriptsWidget = QVBoxLayout()
        self.ScriptsWidget.setSpacing(0)
        self.ScriptsWidget.setObjectName(u"ScriptsWidget")
        self.ScriptsWidget.addWidget(self.ScriptsHeader)
        self.ScriptsWidget.addWidget(self.ScriptsArea)

        self.ScriptsSpacer = QSpacerItem(20, 10, _Minimum, _Fixed)

        self.SidebarLayout = QVBoxLayout(self.SidebarFrame)
        self.SidebarLayout.setSpacing(0)
        self.SidebarLayout.setObjectName(u"SidebarLayout")
        self.SidebarLayout.setContentsMargins(0, 0, 5, 0)
        self.SidebarLayout.addLayout(self.ScriptsWidget)
        self.SidebarLayout.addItem(self.ScriptsSpacer)

        self.FiltersHeader = QPushButton(PluginDialog)
        self.FiltersHeader.setObjectName(u"FiltersHeader")
        self.FiltersHeader.setMinimumSize(QSize(0, 30))
        self.FiltersHeader.setProperty('class', 'head')
        self.FiltersHeader.setFont(font)
        self.FiltersHeader.setCursor(QCursor(_PointingHandCursor))

        self.FiltersWidget = QVBoxLayout()
        self.FiltersWidget.setSpacing(0)
        self.FiltersWidget.setObjectName(u"FiltersWidget")
        self.FiltersWidget.addWidget(self.FiltersHeader)

        self.FiltersGroup = QGroupBox(PluginDialog)
        self.FiltersGroup.setObjectName(u"FiltersGroup")
        self.FiltersGroup.setMinimumSize(QSize(0, 100))

        self.FilterSpacerBeg = QSpacerItem(20, 12, _Minimum, _Fixed)

        self.FiltersAdapter = QVBoxLayout(self.FiltersGroup)
        self.FiltersAdapter.setObjectName(u"FiltersAdapter")
        self.FiltersAdapter.addItem(self.FilterSpacerBeg)

        self.FolderFilter = FilterInputGroup(u'Folder', PluginDialog)
        self.FiltersAdapter.addWidget(self.FolderFilter)

        self.FolderFilterSpacer = QSpacerItem(20, 12, _Minimum, _Fixed)
        self.FiltersAdapter.addItem(self.FolderFilterSpacer)

        self.PrefixFilter = FilterInputGroup('Prefix', PluginDialog)
        self.FiltersAdapter.addWidget(self.PrefixFilter)

        self.PrefixFilterSpacer = QSpacerItem(20, 12, _Minimum, _Fixed)
        self.FiltersAdapter.addItem(self.PrefixFilterSpacer)

        self.ColorFilterWrap = QHBoxLayout()
        self.ColorFilterWrap.setObjectName(u"ColorFilterWrap")

        ColorFilterSpacer = QSpacerItem(40, 26, _Expanding, _Minimum)
        self.ColorFilter = PaletteTool(
            u'ColorFilter',
            (26, 26),
            'Filter',
            True,
            False,
            PluginDialog)
        self.ColorFilterWrap.addItem(ColorFilterSpacer)
        self.ColorFilterWrap.addWidget(self.ColorFilter)
        self.ColorFilterWrap.addItem(ColorFilterSpacer)

        self.FiltersAdapter.addLayout(self.ColorFilterWrap)

        self.FilterSpacerEnd = QSpacerItem(20, 12, _Minimum, _Fixed)
        self.FiltersAdapter.addItem(self.FilterSpacerEnd)

        self.FiltersWidget.addWidget(self.FiltersGroup)

        self.SidebarLayout.addLayout(self.FiltersWidget)

        self.FiltersSpacer = QSpacerItem(20, 14, _Minimum, _Fixed)

        self.SidebarLayout.addItem(self.FiltersSpacer)

        self.MainSplitter.addWidget(self.SidebarFrame)
        self.MainSplitter.setStretchFactor(1,3)

        self.ContentFrame = QFrame(PluginDialog)
        self.ContentLayout = QVBoxLayout(self.ContentFrame)
        self.ContentLayout.setSpacing(0)
        self.ContentLayout.setObjectName(u"ContentLayout")
        self.ContentLayout.setContentsMargins(0, 0, 5, 0)

        self.progressBar = ProgBar(u"progressBar", PluginDialog)

        self.ContentLayout.addWidget(self.progressBar)

        self.ResultsLayout = QHBoxLayout()
        self.ResultsLayout.setObjectName(u"ResultsLayout")
        self.ResultsView = QTreeView(PluginDialog)
        self.ResultsView.setObjectName(u"ResultsView")
        self.ResultsView.setAlternatingRowColors(True)
        self.ResultsView.header().setDefaultAlignment(_AlignHCenter)
        self.ResultsView.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.ResultsView.setEditTriggers(QTreeView.NoEditTriggers)
        self.ResultsView.setContextMenuPolicy(_CustomContextMenu)

        self.ResultsLayout.addWidget(self.ResultsView)

        self.ContentLayout.addLayout(self.ResultsLayout)

        self.ResultsSpacer = QSpacerItem(20, 10, _Minimum, _Fixed)

        self.ContentLayout.addItem(self.ResultsSpacer)

        self.ToolsWidget = QHBoxLayout()
        self.ToolsWidget.setSpacing(6)
        self.ToolsWidget.setObjectName(u"ToolsWidget")
        self.BegSpacer = QSpacerItem(10, 20, _Fixed, _Minimum)

        self.ToolsWidget.addItem(self.BegSpacer)

        self.LabelTool = LabelTool('LabelTool', self.env_desc, PluginDialog)

        self.MidSpacer = QSpacerItem(160, 20, _Expanding, _Minimum)

        self.ToolsWidget.addWidget(self.LabelTool)
        self.ToolsWidget.addItem(self.MidSpacer)

        self.PaletteTool = PaletteTool(
            u'PaletteTool',
            (30, 30),
            'SetColor',
            False,
            True,
            PluginDialog)

        self.EndSpacer = QSpacerItem(10, 20, _Fixed, _Minimum)

        self.ToolsWidget.addWidget(self.PaletteTool)
        self.ToolsWidget.addItem(self.EndSpacer)
        self.ToolsSpacer = QSpacerItem(20, 14, _Minimum, _Fixed)

        self.ContentLayout.addLayout(self.ToolsWidget)
        self.ContentLayout.addItem(self.ToolsSpacer)
        self.ContentLayout.setStretch(0, 0)
        self.ContentLayout.setStretch(1, 8)
        self.ContentLayout.setStretch(2, 2)
        self.ContentLayout.setStretch(3, 0)
        self.ContentLayout.setStretch(4, 1)

        self.MainSplitter.addWidget(self.ContentFrame)
        self.MainSplitter.setCollapsible(0, False)
        self.MainSplitter.setCollapsible(1, False)

        self.MainLayout.setStretch(0, 3)
        self.MainLayout.setStretch(1, 9)
        self.MainLayout.addWidget(self.MainSplitter)

        self.PluginAdapter.addLayout(self.MainLayout)

        self.retranslateUi(PluginDialog)
        QMetaObject.connectSlotsByName(PluginDialog)

    def retranslateUi(self, PluginDialog):
        PluginDialog.setWindowTitle(i18n("IdaClu"))

        self.FolderFilter.setLabel(i18n("FOLDERS"))
        self.PrefixFilter.setLabel(i18n("PREFIXES"))
        self.PaletteTool.setPrefix(i18n('Highlight function'))
        self.FiltersHeader.setText(i18n("FILTERS"))
        self.ScriptsHeader.setText(i18n("TOOLKIT"))
        self.FiltersGroup.setTitle(i18n(""))

