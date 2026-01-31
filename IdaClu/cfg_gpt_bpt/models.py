from re import split

from idaclu.qt_shims import (
    QAbstractItemModel,
    QBrush,
    QColor,
    QHBoxLayout,
    QIcon,
    QLabel,
    QModelIndex,
    QPainter,
    QPixmap,
    QWidget,
    Qt,
    QtCore
)


class ResultNode(object):
    def __init__(self, data):
        self._data = data
        if type(data) == tuple:
            self._data = list(data)
        if type(data) is str or not hasattr(data, '__getitem__'):
            self._data = [data]

        self._columncount = len(self._data)
        self._children = []
        self._parent = None
        self._row = 0

    def data(self, column):
        if column == 0:
            return str(self._data[column]).replace('%', '_')
        elif column >= 1 and column < len(self._data):
            if self._data[column] != None:
                return self._data[column]
            return ""

    def columnCount(self):
        return self._columncount

    def childCount(self):
        return len(self._children)

    def child(self, row):
        if row >= 0 and row < self.childCount():
            return self._children[row]

    def parent(self):
        return self._parent

    def row(self):
        return self._row

    def addChild(self, child):
        child._parent = self
        child._row = len(self._children)
        self._children.append(child)
        self._columncount = max(child.columnCount(), self._columncount)

    def setData(self, column, value):
        if column < 0 or column >= len(self._data):
            return False
        self._data[column] = value
        return True


class ResultModel(QAbstractItemModel):

    def __init__(self, heads, nodes, env_desc):
        super(ResultModel, self).__init__()
        self._root = ResultNode(heads)
        self.env_desc = env_desc
        self.color_col = 8 if env_desc.lib_qt == 'pyqt5' else 7
        self.state_col = 9 if env_desc.lib_qt == 'pyqt5' else 8
        for node in nodes:
            self._root.addChild(node)

    def rowCount(self, index):
        if index.isValid():
            return index.internalPointer().childCount()
        return self._root.childCount()

    def addChild(self, node, _parent):
        if not _parent or not _parent.isValid():
            parent = self._root
        else:
            parent = _parent.internalPointer()
        parent.addChild(node)

    def index(self, row, column, _parent=None):
        if not _parent or not _parent.isValid():
            parent = self._root
        else:
            parent = _parent.internalPointer()

        if not QAbstractItemModel.hasIndex(self, row, column, _parent):
            return QModelIndex()

        child = parent.child(row)
        if child:
            return QAbstractItemModel.createIndex(self, row, column, child)
        else:
            return QModelIndex()

    def parent(self, index):
        if index.isValid():
            p = index.internalPointer().parent()
            if p:
                return QAbstractItemModel.createIndex(self, p.row(), 0, p)
        return QModelIndex()

    def columnCount(self, index):
        if index.isValid():
            return index.internalPointer().columnCount()
        return self._root.columnCount()

    def createDotPixmaps(self, state):
        std_color = QColor(128,128,128)
        bpt_color = QColor(229,12,12)
        gpt_color = QColor(116,170,156)
        colors = [bpt_color, gpt_color]

        total_w = (12 + 4) * len(state)
        px_sup = QPixmap(total_w, 12)
        px_sup.fill(Qt.transparent)

        for i, s in enumerate(state):
            px_sub = QPixmap(12,12)
            px_sub.fill(Qt.transparent)

            pxSize = px_sub.rect().adjusted(1, 1, -1, -1)
            painter_sub = QPainter(px_sub)
            painter_sub.setRenderHint(QPainter.Antialiasing)
            col = colors[i] if s else std_color
            painter_sub.setBrush(col)
            # painter.setPen(QPen(QColor(15,15,15), 1.25))
            painter_sub.drawEllipse(pxSize)
            painter_sub.end()

            px_pos = (12 + 4) * i
            rect = QtCore.QRectF(px_pos, 0, 12, 12)
            painter_sup = QPainter(px_sup)
            painter_sup.drawPixmap(rect, px_sub, QtCore.QRectF(px_sub.rect()))
            painter_sup.end()

        return px_sup

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        node = index.internalPointer()
        if role == Qt.DisplayRole:
            return node.data(index.column())

        elif role == Qt.BackgroundRole:
            node = index.internalPointer()
            rgb_string = node.data(self.color_col)
            if rgb_string and rgb_string != 'rgb(255,255,255)':
                rgb_values = rgb_string.replace("rgb(", "").replace(")", "")
                r, g, b = tuple(map(int, rgb_values.split(",")))
                color = QColor(r, g, b)
                if self.env_desc.lib_qt == 'pyqt5':
                    return color
                elif self.env_desc.lib_qt == 'pyside':
                    brush = QBrush(color)
                    return brush

        elif role == Qt.DecorationRole and index.column() == 0:
            p = index.internalPointer().parent().parent()
            if p:
                state = node.data(self.state_col)
                return QIcon(self.createDotPixmaps(state))
        return None

    def setHeaderData(self, section, orientation, value, role=Qt.EditRole):
        if role != Qt.EditRole or orientation != Qt.Horizontal:
            return False
        result = self._root.setData(section, value)
        if result:
            self.headerDataChanged.emit(orientation, section, section)
        return result

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._root.data(section)
        return None

    def flags(self, index):
        return Qt.ItemIsSelectable|Qt.ItemIsEnabled|Qt.ItemIsEditable

    def setData(self, index, value, role=Qt.EditRole):
        if not index.isValid():
            return False
        node = index.internalPointer()
        if role in [Qt.EditRole, Qt.DecorationRole]:
            col = 0
            if role != Qt.DecorationRole:
                col = 1 if value.startswith('/') else 0
                if value.startswith('rgb'):
                    col = self.color_col
                result = node.setData(col, value)
            else:
                result = node.setData(self.state_col, value)
            if result:
                if self.env_desc.lib_qt == 'pyqt5':
                    if col == 8:
                        self.dataChanged.emit(index.sibling(index.row(), 0), index.sibling(index.row(), 7), [Qt.BackgroundRole])
                    else:
                        if role != Qt.DecorationRole:
                            self.dataChanged.emit(index.sibling(index.row(), col), index.sibling(index.row(), col), [Qt.EditRole])
                        else:
                            self.dataChanged.emit(index.sibling(index.row(), col), index.sibling(index.row(), col), [Qt.DecorationRole])
                elif self.env_desc.lib_qt == 'pyside':
                    if col == 7:
                        self.dataChanged.emit(index.sibling(index.row(), 0), [Qt.BackgroundRole])
                    else:
                        self.dataChanged.emit(index.sibling(index.row(), col), [Qt.EditRole])
            return True
        return False

    def sort(self, column, order, is_child_sort=-1):

        def natural_sort_key(s):
            return [int(text) if text.isdigit() else text.lower() for text in split('([0-9]+)', s)]

        if is_child_sort != -1:
            self.beginResetModel()
            if is_child_sort:
                for i, child in enumerate(self._root._children):
                    self._root._children[i]._children.sort(key=lambda x: x.data(column), reverse=(order == QtCore.Qt.DescendingOrder))
            else:
                self._root._children.sort(key=lambda x: natural_sort_key(x.data(column)), reverse=(order == QtCore.Qt.DescendingOrder))
            self.endResetModel()
