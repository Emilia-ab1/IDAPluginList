# Based on original idea and PoC by Caroline 'By0ute' Beyne
# https://github.com/By0ute/pyqt-collapsible-widget

from idaclu.qt_shims import (
    QComboBox,
    QColor,
    QCoreApplication,
    QCursor,
    QEvent,
    QFont,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPainter,
    QPoint,
    QPointF,
    QProgressBar,
    QPushButton,
    QSize,
    QSizePolicy,
    QSpacerItem,
    QStandardItem,
    QStyledItemDelegate,
    Qt,
    QThread,
    QVBoxLayout,
    QWidget,
    Signal
)
from idaclu import plg_utils


def i18n(tstr):
    return QCoreApplication.translate("PluginDialog", tstr, None)


class LabelTool(QWidget):
    def __init__(self, name, env_desc, parent=None):
        super(LabelTool, self).__init__(parent)
        self.setObjectName(name)

        self.env_desc = env_desc
        self.font = QFont('MS Shell Dlg 2', 8, QFont.Bold)
        self.layout = QHBoxLayout()
        self.layout.addWidget(self.initModeToggle(parent))
        self.layout.addLayout(self.initLabelComp(parent))
        for actn in ['SetLabel', 'ClsLabel']:
            self.layout.addWidget(self.initActionButton(actn, parent))
        self.retranslateUi()
        self.setLayout(self.layout)


    def initActionButton(self, ref, parent):
        _PointingHandCursor = Qt.PointingHandCursor

        btn_name = "{}Button".format(ref)
        btn = QPushButton()
        btn.setObjectName(u"{}".format(btn_name))
        btn.setMinimumSize(QSize(75, 30))
        btn.setMaximumSize(QSize(75, 30))
        btn.setFont(self.font)
        btn.setEnabled(False)
        setattr(self, btn_name, btn)
        return btn

    def initModeToggle(self, parent):
        _PointingHandCursor = Qt.PointingHandCursor

        toggle = QPushButton(parent)
        toggle.setObjectName(u"ModeToggle")
        toggle.setMinimumSize(QSize(30, 30))
        toggle.setMaximumSize(QSize(30, 30))
        toggle.setFont(self.font)
        toggle.setCheckable(True)
        toggle.setCursor(QCursor(_PointingHandCursor))
        self.ModeToggle = toggle
        return toggle

    def initLabelComp(self, parent):
        _PointingHandCursor = Qt.PointingHandCursor

        comp = QHBoxLayout()
        comp.setSpacing(0)
        comp.setObjectName(u"LabelComp")

        label = QPushButton(parent)
        label.setObjectName(u"LabelToggle")
        label.setCursor(QCursor(_PointingHandCursor))
        label.setMinimumSize(QSize(75, 30))
        label.setMaximumSize(QSize(75, 30))
        label.setFont(self.font)
        label.setCheckable(False)
        label.setAutoExclusive(False)
        self.LabelToggle = label

        edit = QLineEdit(parent)
        edit.setObjectName(u"LabelEdit")
        edit.setMaximumSize(QSize(16777215, 30))
        edit.setPlaceholderText("Insert prefix")
        self.LabelEdit = edit

        comp.addWidget(self.LabelToggle)
        comp.addWidget(self.LabelEdit)
        comp.setStretch(0, 2)
        comp.setStretch(1, 5)
        return comp

    def setEnabled(self, state):
        self.SetLabelButton.setEnabled(state)
        self.ClsLabelButton.setEnabled(state)

    def getLabelName(self):
        return self.LabelEdit.text()

    def setModeHandler(self, handler):
        self.ModeToggle.clicked.connect(handler)

    def setLabelHandler(self, handler):
        self.LabelToggle.clicked.connect(handler)

    def setSetHandler(self, handler):
        self.SetLabelButton.clicked.connect(handler)

    def setClsHandler(self, handler):
        self.ClsLabelButton.clicked.connect(handler)

    def retranslateUi(self):
        self.ModeToggle.setText(i18n("R"))
        self.LabelToggle.setText(i18n("PREFIX"))
        self.SetLabelButton.setText(i18n("ADD"))
        self.ClsLabelButton.setText(i18n("CLEAR"))
        self.ModeToggle.setToolTip(i18n("Toggle recursive mode on/off"))
        self.LabelToggle.setToolTip(i18n("Switch between Prefix/Folder modes"))

class ProgBar(QProgressBar):
    def __init__(self, name, parent=None):
        super(ProgBar, self).__init__(parent)

        self.setObjectName(name)
        self.setMinimumSize(QSize(0, 5))
        self.setMaximumSize(QSize(16777215, 5))
        self.setValue(24)
        self.setTextVisible(False)
        self.setVisible(False)

        self.worker = Worker()
        self.worker.updateProgress.connect(self.setProgress)

    def setProgress(self, progress):
        if progress == 0:
            self.setVisible(False)
        elif progress == 100:
            self.setVisible(False)
            self.setValue(0)
        else:
            self.setVisible(True)
            self.setValue(progress)

    def updateProgress(self, progress):
        self.worker.updateProgress.emit(progress)

class ColorButton(QPushButton):
    def __init__(self, name, size=(30, 30), is_enbl=True, is_excl=True, parent=None):
        QWidget.__init__(self, parent=parent)

        self.setObjectName(name)
        self.setMinimumSize(QSize(*size))
        self.setMaximumSize(QSize(*size))
        self.setCheckable(True)
        self.setAutoExclusive(is_excl)
        self.setEnabled(is_enbl)
        self.setCursor(QCursor(Qt.PointingHandCursor))

class Worker(QThread):
    updateProgress = Signal(int)

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        for i in range(1, 101):
            self.updateProgress.emit(i)
            # time.sleep(0.01)


class PaletteTool(QWidget):
    COLOR_NAME = 0
    COLOR_VAL = 1

    def __init__(self, name, size, pref, is_enbl=True, is_excl=True, parent=None):
        # qt_shims.QWidget.__init__(self, parent=parent)
        super(PaletteTool, self).__init__(parent)
        self.colors = [
            ("yellow", (255,255,191)),
            ("blue", (199,255,255)),
            ("green", (191,255,191)),
            ("pink", (255,191,239)),
            ("none", (255,255,255))
        ]

        self.setObjectName(name)
        self.layout = QHBoxLayout()

        for name, _ in self.colors:
            btn_name = '{}{}'.format(pref, name.capitalize())
            btn_obj = ColorButton(u"{}".format(btn_name), size, is_enbl, is_excl, parent)
            btn_obj.setProperty('class','plt-btn plt-btn-{}'.format(name))
            btn_obj.setText("")
            self.layout.addWidget(btn_obj)
        self.setLayout(self.layout)

    def changeFuncColor(self):
        pass

    def setClickHandler(self, handler):
        for _, btn in self.enumButtons():
            btn.clicked.connect(handler)

    def setPrefix(self, pref):
        for _, btn in self.enumButtons():
            color = str(btn.objectName()).replace('SetColor', '').lower()
            btn.setToolTip("{} {}".format(pref, i18n(color)))

    def enumButtons(self):
        for i in range(self.layout.count()):
            widget = self.layout.itemAt(i).widget()
            if isinstance(widget, QPushButton):
                yield (i, widget)

    def setEnabled(self, state):
        for _, btn in self.enumButtons():
            btn.setEnabled(state)

    def getSelectedColors(self):
        colors = []
        for i, btn in self.enumButtons():
            if btn.isChecked():
                color_val = self.colors[i][PaletteTool.COLOR_VAL]
                colors.append(plg_utils.RgbColor(color_val))
        return colors

class FilterInputGroup(QWidget):
    def __init__(self, name, parent=None):
        super(FilterInputGroup, self).__init__(parent)

        _Fixed = QSizePolicy.Fixed
        _Minimum = QSizePolicy.Minimum
        Spacer = QSpacerItem(14, 26, _Fixed, _Minimum)

        self.setObjectName(u'{}Filter'.format(name))
        self._layout = QHBoxLayout()
        self._layout.setSpacing(0)
        self._layout.addItem(Spacer)
        self._layout.addWidget(self.initText(name, self))
        self._layout.addWidget(self.initSelect(name))
        self._layout.addItem(Spacer)
        self._layout.setStretch(0, 0)
        self._layout.setStretch(1, 5)
        self._layout.setStretch(2, 7)
        self._layout.setStretch(3, 0)
        self.setLayout(self._layout)

    def initText(self, name, parent=None):
        self._label = QPushButton(parent)
        self._label.setObjectName(u'{}Header'.format(name))
        self._label.setMinimumSize(QSize(96, 26))
        self._label.setMaximumSize(QSize(96, 26))
        self._label.setProperty('class', 'select-head')
        return self._label

    def initSelect(self, name, parent=None):
        self._select = CheckableComboBox()
        self._select.setObjectName(u'{}Select'.format(name))
        self._select.setEnabled(True)
        self._select.setAutoFillBackground(False)
        self._select.setMinimumSize(QSize(16777215, 26))
        self._select.setMaximumSize(QSize(16777215, 26))
        return self._select

    def setPlaceholder(self, pholder):
        self._select.lineEdit().setPlaceholderText(pholder)

    def setLabel(self, text):
        self._label.setText(text)

    def addItems(self, items):
        self._select.addItems(items)

    def addItemNew(self, item):
        self._select.addItemNew(item)

    def setEnabled(self, state=False):
        self._select.setEnabled()

    def setParent(self, parent):  # is it used only in "unset" scenario
        self._label.setParent(parent)
        self._select.setParent(parent)
        self.setParent(parent)

    def setText(self, text):
        self._select.lineEdit().setText(text)

    def getData(self):
        return self._select.getData().split('; ')


class CheckableComboBox(QComboBox):
    def __init__(self):
        super(CheckableComboBox, self).__init__()
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.closeOnLineEditClick = False
        self.lineEdit().installEventFilter(self)
        self.view().viewport().installEventFilter(self)
        self.model().dataChanged.connect(self.updateLineEditField)
        self.itemDelegate = QStyledItemDelegate(self)
        self.setItemDelegate(self.itemDelegate)

    def hidePopup(self):
        super(CheckableComboBox, self).hidePopup()
        self.startTimer(100)

    def addItems(self, items, itemList=None):
        for indx, text in enumerate(items):
            try:
                data = itemList[indx]
            except (TypeError, IndexError):
                data = None
            self.addItem(text, data)

    def addItemNew(self, text, userData=None):
        for row in range(self.model().rowCount()):
            item = self.model().item(row)
            if ((item and (item.text() == text)) or
                (userData and item.data() == userData)):
                return False
        self.addItem(text, userData)
        return True

    def addItem(self, text, userData=None):
        item = QStandardItem()
        item.setText(text)
        if not userData is None:
            item.setData(userData)
        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
        item.setData(Qt.Unchecked, Qt.CheckStateRole)
        self.model().appendRow(item)

    def eventFilter(self, widget, event):
        if widget == self.lineEdit():
            if event.type() == QEvent.MouseButtonRelease:
                if self.closeOnLineEditClick:
                    self.hidePopup()
                else:
                    self.showPopup()
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)
        if widget == self.view().viewport():
            if event.type() == QEvent.MouseButtonRelease:
                indx = self.view().indexAt(event.pos())
                item = self.model().item(indx.row())

                if item.checkState() == Qt.Checked:
                    item.setCheckState(Qt.Unchecked)
                else:
                    item.setCheckState(Qt.Checked)
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)

    def updateLineEditField(self):
        text_container = []
        for i in range(self.model().rowCount()):
            if self.model().item(i).checkState() == Qt.Checked:
                text_container.append(self.model().item(i).text())
            text_string = '; '.join(text_container)
            self.lineEdit().setText(text_string)

    def getData(self):
        return self.lineEdit().text()

    def clearData(self):
        self.clear()


class FrameLayout(QWidget):
    def __init__(self, parent=None, title=None, env=None):
        self.env_desc = env
        QWidget.__init__(self, parent=parent)

        self._is_collasped = True
        self._title_frame = None
        self._content, self._content_layout = (None, None)

        title_frame = self.initTitleFrame(title, self._is_collasped)
        content_widget = self.initContent(self._is_collasped)

        self._main_v_layout = QVBoxLayout(self)
        self._main_v_layout.addWidget(title_frame)
        self._main_v_layout.addWidget(content_widget)

        self.initCollapsable()

    def initTitleFrame(self, title, collapsed):
        self._title_frame = self.TitleFrame(
            title=title,
            collapsed=collapsed,
            env=self.env_desc)
        return self._title_frame

    def initContent(self, collapsed):
        self._content = QWidget()
        self._content_layout = QVBoxLayout()

        self._content.setLayout(self._content_layout)
        self._content.setVisible(not collapsed)

        return self._content

    def addWidget(self, widget):
        self._content_layout.addWidget(widget)

    def initCollapsable(self):
        self._title_frame.clicked.connect(self.toggleCollapsed)

    def toggleCollapsed(self):
        self._content.setVisible(self._is_collasped)
        self._is_collasped = not self._is_collasped
        self._title_frame._arrow.setArrow(int(self._is_collasped))


    class TitleFrame(QFrame):

        clicked = Signal()
        def __init__(self, parent=None, title="", collapsed=False, env=None):
            QFrame.__init__(self, parent=parent)
            self.env_desc = env
            self.setMinimumHeight(24)
            self.move(QPoint(24, 0))

            self._hlayout = QHBoxLayout(self)
            self._hlayout.setContentsMargins(0, 0, 0, 0)
            self._hlayout.setSpacing(0)

            self._arrow = None
            self._title = None

            self._hlayout.addWidget(self.initArrow(collapsed))
            self._hlayout.addWidget(self.initTitle(title))

        def initArrow(self, collapsed):
            self._arrow = FrameLayout.Arrow(collapsed=collapsed, env=self.env_desc)
            return self._arrow

        def initTitle(self, title=None):
            self._title = QLabel(title)
            self._title.setMinimumHeight(24)
            self._title.move(QPoint(24, 0))

            return self._title

        def mousePressEvent(self, event):
            self.clicked.emit()
            return super(FrameLayout.TitleFrame, self).mousePressEvent(event)


    class Arrow(QFrame):
        def __init__(self, parent=None, collapsed=False, env=None):
            QFrame.__init__(self, parent=parent)
            self.env_desc = env
            self.setMaximumSize(24, 24)

            # horizontal == 0
            ha_point1 = QPointF(7.0, 8.0)
            ha_point2 = QPointF(17.0, 8.0)
            ha_point3 = QPointF(12.0, 13.0)
            self._arrow_horizontal = (ha_point1, ha_point2, ha_point3)
            # vertical == 1
            va_point1 = QPointF(8.0, 7.0)
            va_point2 = QPointF(13.0, 12.0)
            va_point3 = QPointF(8.0, 17.0)
            self._arrow_vertical = (va_point1, va_point2, va_point3)
            # arrow
            self._arrow = None
            self.setArrow(int(collapsed))

        def setArrow(self, arrow_dir):
            if arrow_dir:
                self._arrow = self._arrow_vertical
            else:
                self._arrow = self._arrow_horizontal

        def paintEvent(self, event):
            painter = QPainter()
            painter.begin(self)
            painter.setBrush(QColor(192, 192, 192))
            painter.setPen(QColor(64, 64, 64))
            if self.env_desc.lib_qt == 'pyqt5':
                painter.drawPolygon(*self._arrow)
            else:  # 'pyside'
                painter.drawPolygon(self._arrow)
            painter.end()
