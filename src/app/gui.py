from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMainWindow
from src.cryptographic_methods import polybius_square, gost_28147_89, rsa, tiger, eds, exceptions
from src.app import services


class UiMainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setup_ui(self)
        self.setup_handlers()

    def setup_ui(self, main_window: "UiMainWindow"):
        main_window.setObjectName("MainWindow")
        main_window.resize(1000, 600)
        main_window.setMinimumSize(QtCore.QSize(1000, 600))
        main_window.setMaximumSize(QtCore.QSize(1000, 600))
        self.centralwidget = QtWidgets.QWidget(main_window)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.tabWidget.setFont(font)
        self.tabWidget.setObjectName("tabWidget")
        self.polybiusTab = QtWidgets.QWidget()
        self.polybiusTab.setEnabled(True)
        self.polybiusTab.setObjectName("polybiusTab")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.polybiusTab)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_14 = QtWidgets.QLabel(self.polybiusTab)
        self.label_14.setObjectName("label_14")
        self.verticalLayout_2.addWidget(self.label_14)
        self.line_3 = QtWidgets.QFrame(self.polybiusTab)
        self.line_3.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.line_3.sizePolicy().hasHeightForWidth())
        self.line_3.setSizePolicy(sizePolicy)
        self.line_3.setAutoFillBackground(False)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_3.setMidLineWidth(15)
        self.line_3.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_3.setObjectName("line_3")
        self.verticalLayout_2.addWidget(self.line_3)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetMaximumSize)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout()
        self.verticalLayout_4.setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetMaximumSize)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.label_2 = QtWidgets.QLabel(self.polybiusTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_4.addWidget(self.label_2)
        self.polybiusOriginalTextEdit = QtWidgets.QTextEdit(self.polybiusTab)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.polybiusOriginalTextEdit.setFont(font)
        self.polybiusOriginalTextEdit.setObjectName("polybiusOriginalTextEdit")
        self.verticalLayout_4.addWidget(self.polybiusOriginalTextEdit)
        self.horizontalLayout.addLayout(self.verticalLayout_4)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetMaximumSize)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label = QtWidgets.QLabel(self.polybiusTab)
        self.label.setObjectName("label")
        self.verticalLayout_3.addWidget(self.label)
        self.poybiusConvertedEditText = QtWidgets.QTextEdit(self.polybiusTab)
        self.poybiusConvertedEditText.setReadOnly(True)
        self.poybiusConvertedEditText.setObjectName("poybiusConvertedEditText")
        self.verticalLayout_3.addWidget(self.poybiusConvertedEditText)
        self.horizontalLayout.addLayout(self.verticalLayout_3)
        self.verticalLayout_5 = QtWidgets.QVBoxLayout()
        self.verticalLayout_5.setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetMinimumSize)
        self.verticalLayout_5.setSpacing(6)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.label_3 = QtWidgets.QLabel(self.polybiusTab)
        self.label_3.setMaximumSize(QtCore.QSize(250, 16777215))
        self.label_3.setObjectName("label_3")
        self.verticalLayout_5.addWidget(self.label_3)
        self.textEdit = QtWidgets.QTextEdit(self.polybiusTab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.textEdit.sizePolicy().hasHeightForWidth())
        self.textEdit.setSizePolicy(sizePolicy)
        self.textEdit.setMaximumSize(QtCore.QSize(225, 16777215))
        self.textEdit.setReadOnly(True)
        self.textEdit.setObjectName("textEdit")
        self.verticalLayout_5.addWidget(self.textEdit)
        self.horizontalLayout.addLayout(self.verticalLayout_5)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.polybiusEncryptRadioButton = QtWidgets.QRadioButton(self.polybiusTab)
        self.polybiusEncryptRadioButton.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.polybiusEncryptRadioButton.setObjectName("polybiusEncryptRadioButton")
        self.horizontalLayout_2.addWidget(self.polybiusEncryptRadioButton)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem1)
        self.polybiusDecryptRadioButton = QtWidgets.QRadioButton(self.polybiusTab)
        self.polybiusDecryptRadioButton.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.polybiusDecryptRadioButton.setChecked(True)
        self.polybiusDecryptRadioButton.setObjectName("polybiusDecryptRadioButton")
        self.horizontalLayout_3.addWidget(self.polybiusDecryptRadioButton)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem2)
        self.polybiusButton = QtWidgets.QPushButton(self.polybiusTab)
        self.polybiusButton.setMinimumSize(QtCore.QSize(0, 0))
        self.polybiusButton.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.polybiusButton.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.polybiusButton.setAutoFillBackground(False)
        self.polybiusButton.setAutoRepeatDelay(302)
        self.polybiusButton.setObjectName("polybiusButton")
        self.horizontalLayout_4.addWidget(self.polybiusButton)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.tabWidget.addTab(self.polybiusTab, "")
        self.gost_28147_89_Tab = QtWidgets.QWidget()
        self.gost_28147_89_Tab.setObjectName("gost_28147_89_Tab")
        self.verticalLayout_13 = QtWidgets.QVBoxLayout(self.gost_28147_89_Tab)
        self.verticalLayout_13.setObjectName("verticalLayout_13")
        self.label_15 = QtWidgets.QLabel(self.gost_28147_89_Tab)
        self.label_15.setObjectName("label_15")
        self.verticalLayout_13.addWidget(self.label_15)
        self.line_4 = QtWidgets.QFrame(self.gost_28147_89_Tab)
        self.line_4.setMidLineWidth(9)
        self.line_4.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_4.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_4.setObjectName("line_4")
        self.verticalLayout_13.addWidget(self.line_4)
        self.horizontalLayout_14 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_14.setObjectName("horizontalLayout_14")
        self.verticalLayout_14 = QtWidgets.QVBoxLayout()
        self.verticalLayout_14.setObjectName("verticalLayout_14")
        self.label_16 = QtWidgets.QLabel(self.gost_28147_89_Tab)
        self.label_16.setObjectName("label_16")
        self.verticalLayout_14.addWidget(self.label_16)
        self.gostKeyLineEdit = QtWidgets.QLineEdit(self.gost_28147_89_Tab)
        self.gostKeyLineEdit.setObjectName("gostKeyLineEdit")
        self.verticalLayout_14.addWidget(self.gostKeyLineEdit)
        self.label_17 = QtWidgets.QLabel(self.gost_28147_89_Tab)
        self.label_17.setObjectName("label_17")
        self.verticalLayout_14.addWidget(self.label_17)
        self.gostOriginalTextEdit = QtWidgets.QTextEdit(self.gost_28147_89_Tab)
        self.gostOriginalTextEdit.setObjectName("gostOriginalTextEdit")
        self.verticalLayout_14.addWidget(self.gostOriginalTextEdit)
        self.horizontalLayout_14.addLayout(self.verticalLayout_14)
        self.verticalLayout_15 = QtWidgets.QVBoxLayout()
        self.verticalLayout_15.setObjectName("verticalLayout_15")
        self.label_19 = QtWidgets.QLabel(self.gost_28147_89_Tab)
        self.label_19.setObjectName("label_19")
        self.verticalLayout_15.addWidget(self.label_19)
        self.macLineEdit = QtWidgets.QLineEdit(self.gost_28147_89_Tab)
        self.macLineEdit.setReadOnly(True)
        self.macLineEdit.setObjectName("macLineEdit")
        self.verticalLayout_15.addWidget(self.macLineEdit)
        self.label_18 = QtWidgets.QLabel(self.gost_28147_89_Tab)
        self.label_18.setObjectName("label_18")
        self.verticalLayout_15.addWidget(self.label_18)
        self.gostConvertedTextEdit = QtWidgets.QTextEdit(self.gost_28147_89_Tab)
        self.gostConvertedTextEdit.setReadOnly(True)
        self.gostConvertedTextEdit.setObjectName("gostConvertedTextEdit")
        self.verticalLayout_15.addWidget(self.gostConvertedTextEdit)
        self.horizontalLayout_14.addLayout(self.verticalLayout_15)
        self.verticalLayout_13.addLayout(self.horizontalLayout_14)
        self.horizontalLayout_15 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_15.setObjectName("horizontalLayout_15")
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_15.addItem(spacerItem3)
        self.gostEncryptRadioButton = QtWidgets.QRadioButton(self.gost_28147_89_Tab)
        self.gostEncryptRadioButton.setChecked(True)
        self.gostEncryptRadioButton.setObjectName("gostEncryptRadioButton")
        self.horizontalLayout_15.addWidget(self.gostEncryptRadioButton)
        self.verticalLayout_13.addLayout(self.horizontalLayout_15)
        self.horizontalLayout_16 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_16.setObjectName("horizontalLayout_16")
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_16.addItem(spacerItem4)
        self.gostDecryptRadioButton = QtWidgets.QRadioButton(self.gost_28147_89_Tab)
        self.gostDecryptRadioButton.setObjectName("gostDecryptRadioButton")
        self.horizontalLayout_16.addWidget(self.gostDecryptRadioButton)
        self.verticalLayout_13.addLayout(self.horizontalLayout_16)
        self.horizontalLayout_17 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_17.setObjectName("horizontalLayout_17")
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_17.addItem(spacerItem5)
        self.gostButton = QtWidgets.QPushButton(self.gost_28147_89_Tab)
        self.gostButton.setObjectName("gostButton")
        self.horizontalLayout_17.addWidget(self.gostButton)
        self.verticalLayout_13.addLayout(self.horizontalLayout_17)
        self.tabWidget.addTab(self.gost_28147_89_Tab, "")
        self.rsaTab = QtWidgets.QWidget()
        self.rsaTab.setObjectName("rsaTab")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.rsaTab)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.label_13 = QtWidgets.QLabel(self.rsaTab)
        self.label_13.setMouseTracking(True)
        self.label_13.setLineWidth(0)
        self.label_13.setWordWrap(True)
        self.label_13.setObjectName("label_13")
        self.verticalLayout_6.addWidget(self.label_13)
        self.line_2 = QtWidgets.QFrame(self.rsaTab)
        self.line_2.setLineWidth(1)
        self.line_2.setMidLineWidth(7)
        self.line_2.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_2.setObjectName("line_2")
        self.verticalLayout_6.addWidget(self.line_2)
        self.verticalLayout_8 = QtWidgets.QVBoxLayout()
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.label_4 = QtWidgets.QLabel(self.rsaTab)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_6.addWidget(self.label_4)
        self.pLineEdit = QtWidgets.QLineEdit(self.rsaTab)
        self.pLineEdit.setObjectName("pLineEdit")
        self.horizontalLayout_6.addWidget(self.pLineEdit)
        self.label_5 = QtWidgets.QLabel(self.rsaTab)
        self.label_5.setObjectName("label_5")
        self.horizontalLayout_6.addWidget(self.label_5)
        self.qLineEdit = QtWidgets.QLineEdit(self.rsaTab)
        self.qLineEdit.setObjectName("qLineEdit")
        self.horizontalLayout_6.addWidget(self.qLineEdit)
        spacerItem6 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem6)
        spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem7)
        spacerItem8 = QtWidgets.QSpacerItem(60, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem8)
        self.generateKeysButton = QtWidgets.QPushButton(self.rsaTab)
        self.generateKeysButton.setObjectName("generateKeysButton")
        self.horizontalLayout_6.addWidget(self.generateKeysButton)
        self.verticalLayout_8.addLayout(self.horizontalLayout_6)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.label_7 = QtWidgets.QLabel(self.rsaTab)
        self.label_7.setObjectName("label_7")
        self.horizontalLayout_7.addWidget(self.label_7)
        self.publicKeyLineEdit = QtWidgets.QLineEdit(self.rsaTab)
        self.publicKeyLineEdit.setReadOnly(True)
        self.publicKeyLineEdit.setObjectName("publicKeyLineEdit")
        self.horizontalLayout_7.addWidget(self.publicKeyLineEdit)
        self.label_6 = QtWidgets.QLabel(self.rsaTab)
        self.label_6.setObjectName("label_6")
        self.horizontalLayout_7.addWidget(self.label_6)
        self.privateKeyLineEdit = QtWidgets.QLineEdit(self.rsaTab)
        self.privateKeyLineEdit.setReadOnly(True)
        self.privateKeyLineEdit.setObjectName("privateKeyLineEdit")
        self.horizontalLayout_7.addWidget(self.privateKeyLineEdit)
        self.verticalLayout_8.addLayout(self.horizontalLayout_7)
        self.verticalLayout_6.addLayout(self.verticalLayout_8)
        self.line = QtWidgets.QFrame(self.rsaTab)
        self.line.setMidLineWidth(18)
        self.line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line.setObjectName("line")
        self.verticalLayout_6.addWidget(self.line)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout()
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.label_8 = QtWidgets.QLabel(self.rsaTab)
        self.label_8.setObjectName("label_8")
        self.verticalLayout_7.addWidget(self.label_8)
        self.rsaKeyLineEdit = QtWidgets.QLineEdit(self.rsaTab)
        self.rsaKeyLineEdit.setObjectName("rsaKeyLineEdit")
        self.verticalLayout_7.addWidget(self.rsaKeyLineEdit)
        self.label_9 = QtWidgets.QLabel(self.rsaTab)
        self.label_9.setObjectName("label_9")
        self.verticalLayout_7.addWidget(self.label_9)
        self.rsaOriginalTextEdit = QtWidgets.QTextEdit(self.rsaTab)
        self.rsaOriginalTextEdit.setObjectName("rsaOriginalTextEdit")
        self.verticalLayout_7.addWidget(self.rsaOriginalTextEdit)
        self.horizontalLayout_5.addLayout(self.verticalLayout_7)
        self.verticalLayout_9 = QtWidgets.QVBoxLayout()
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.label_10 = QtWidgets.QLabel(self.rsaTab)
        self.label_10.setObjectName("label_10")
        self.verticalLayout_9.addWidget(self.label_10)
        self.rsaConvertedTextEdit = QtWidgets.QTextEdit(self.rsaTab)
        self.rsaConvertedTextEdit.setReadOnly(True)
        self.rsaConvertedTextEdit.setObjectName("rsaConvertedTextEdit")
        self.verticalLayout_9.addWidget(self.rsaConvertedTextEdit)
        self.horizontalLayout_5.addLayout(self.verticalLayout_9)
        self.verticalLayout_6.addLayout(self.horizontalLayout_5)
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                            QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_8.addItem(spacerItem9)
        self.rsaEncryptRadioButton = QtWidgets.QRadioButton(self.rsaTab)
        self.rsaEncryptRadioButton.setChecked(True)
        self.rsaEncryptRadioButton.setObjectName("rsaEncryptRadioButton")
        self.horizontalLayout_8.addWidget(self.rsaEncryptRadioButton)
        self.verticalLayout_6.addLayout(self.horizontalLayout_8)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        spacerItem10 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                             QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_9.addItem(spacerItem10)
        self.rsaDecryptRadioButton = QtWidgets.QRadioButton(self.rsaTab)
        self.rsaDecryptRadioButton.setObjectName("rsaDecryptRadioButton")
        self.horizontalLayout_9.addWidget(self.rsaDecryptRadioButton)
        self.verticalLayout_6.addLayout(self.horizontalLayout_9)
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        spacerItem11 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                             QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_10.addItem(spacerItem11)
        self.rsaButton = QtWidgets.QPushButton(self.rsaTab)
        self.rsaButton.setObjectName("rsaButton")
        self.horizontalLayout_10.addWidget(self.rsaButton)
        self.verticalLayout_6.addLayout(self.horizontalLayout_10)
        self.tabWidget.addTab(self.rsaTab, "")
        self.tigerTab = QtWidgets.QWidget()
        self.tigerTab.setObjectName("tigerTab")
        self.verticalLayout_10 = QtWidgets.QVBoxLayout(self.tigerTab)
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.label_20 = QtWidgets.QLabel(self.tigerTab)
        self.label_20.setWordWrap(True)
        self.label_20.setObjectName("label_20")
        self.verticalLayout_10.addWidget(self.label_20)
        self.line_5 = QtWidgets.QFrame(self.tigerTab)
        self.line_5.setMidLineWidth(9)
        self.line_5.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_5.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_5.setObjectName("line_5")
        self.verticalLayout_10.addWidget(self.line_5)
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.verticalLayout_11 = QtWidgets.QVBoxLayout()
        self.verticalLayout_11.setObjectName("verticalLayout_11")
        self.label_11 = QtWidgets.QLabel(self.tigerTab)
        self.label_11.setObjectName("label_11")
        self.verticalLayout_11.addWidget(self.label_11)
        self.tigerOriginalTextEdit = QtWidgets.QTextEdit(self.tigerTab)
        self.tigerOriginalTextEdit.setObjectName("tigerOriginalTextEdit")
        self.verticalLayout_11.addWidget(self.tigerOriginalTextEdit)
        self.horizontalLayout_11.addLayout(self.verticalLayout_11)
        self.verticalLayout_12 = QtWidgets.QVBoxLayout()
        self.verticalLayout_12.setObjectName("verticalLayout_12")
        self.label_12 = QtWidgets.QLabel(self.tigerTab)
        self.label_12.setObjectName("label_12")
        self.verticalLayout_12.addWidget(self.label_12)
        self.tigerHashTextEdit = QtWidgets.QTextEdit(self.tigerTab)
        self.tigerHashTextEdit.setReadOnly(True)
        self.tigerHashTextEdit.setObjectName("tigerHashTextEdit")
        self.verticalLayout_12.addWidget(self.tigerHashTextEdit)
        self.horizontalLayout_11.addLayout(self.verticalLayout_12)
        self.verticalLayout_10.addLayout(self.horizontalLayout_11)
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_13.setObjectName("horizontalLayout_13")
        spacerItem12 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                             QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_13.addItem(spacerItem12)
        self.tigerButton = QtWidgets.QPushButton(self.tigerTab)
        self.tigerButton.setObjectName("tigerButton")
        self.horizontalLayout_13.addWidget(self.tigerButton)
        self.verticalLayout_10.addLayout(self.horizontalLayout_13)
        self.tabWidget.addTab(self.tigerTab, "")
        self.edsTab = QtWidgets.QWidget()
        self.edsTab.setObjectName("edsTab")
        self.verticalLayout_16 = QtWidgets.QVBoxLayout(self.edsTab)
        self.verticalLayout_16.setObjectName("verticalLayout_16")
        self.label_21 = QtWidgets.QLabel(self.edsTab)
        self.label_21.setWordWrap(True)
        self.label_21.setObjectName("label_21")
        self.verticalLayout_16.addWidget(self.label_21)
        self.line_6 = QtWidgets.QFrame(self.edsTab)
        self.line_6.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_6.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_6.setObjectName("line_6")
        self.verticalLayout_16.addWidget(self.line_6)
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        self.label_25 = QtWidgets.QLabel(parent=self.edsTab)
        self.label_25.setObjectName("label_25")
        self.horizontalLayout_12.addWidget(self.label_25)
        self.edsKeyLineEdit = QtWidgets.QLineEdit(parent=self.edsTab)
        self.edsKeyLineEdit.setObjectName("edsKeyLineEdit")
        self.horizontalLayout_12.addWidget(self.edsKeyLineEdit)
        spacerItem13 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                             QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_12.addItem(spacerItem13)
        spacerItem14 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                             QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_12.addItem(spacerItem14)
        spacerItem15 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                             QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_12.addItem(spacerItem15)
        self.verticalLayout_16.addLayout(self.horizontalLayout_12)
        self.horizontalLayout_18 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_18.setObjectName("horizontalLayout_18")
        self.verticalLayout_17 = QtWidgets.QVBoxLayout()
        self.verticalLayout_17.setObjectName("verticalLayout_17")
        self.label_22 = QtWidgets.QLabel(self.edsTab)
        self.label_22.setObjectName("label_22")
        self.verticalLayout_17.addWidget(self.label_22)
        self.edsOriginalTextEdit = QtWidgets.QTextEdit(self.edsTab)
        self.edsOriginalTextEdit.setObjectName("edsOriginalTextEdit")
        self.verticalLayout_17.addWidget(self.edsOriginalTextEdit)
        self.horizontalLayout_18.addLayout(self.verticalLayout_17)
        self.verticalLayout_18 = QtWidgets.QVBoxLayout()
        self.verticalLayout_18.setObjectName("verticalLayout_18")
        self.label_23 = QtWidgets.QLabel(self.edsTab)
        self.label_23.setObjectName("label_23")
        self.verticalLayout_18.addWidget(self.label_23)
        self.edsHashTextEdit = QtWidgets.QTextEdit(self.edsTab)
        self.edsHashTextEdit.setReadOnly(False)
        self.edsHashTextEdit.setObjectName("edsHashTextEdit")
        self.verticalLayout_18.addWidget(self.edsHashTextEdit)
        self.horizontalLayout_18.addLayout(self.verticalLayout_18)
        self.verticalLayout_19 = QtWidgets.QVBoxLayout()
        self.verticalLayout_19.setObjectName("verticalLayout_19")
        self.label_24 = QtWidgets.QLabel(self.edsTab)
        self.label_24.setObjectName("label_24")
        self.verticalLayout_19.addWidget(self.label_24)
        self.edsTextEdit = QtWidgets.QTextEdit(self.edsTab)
        self.edsTextEdit.setReadOnly(False)
        self.edsTextEdit.setObjectName("edsTextEdit")
        self.verticalLayout_19.addWidget(self.edsTextEdit)
        self.horizontalLayout_18.addLayout(self.verticalLayout_19)
        self.verticalLayout_16.addLayout(self.horizontalLayout_18)
        self.horizontalLayout_19 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_19.setObjectName("horizontalLayout_19")
        spacerItem13 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                             QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_19.addItem(spacerItem13)
        self.generateEdsButton = QtWidgets.QPushButton(self.edsTab)
        self.generateEdsButton.setObjectName("generateEdsButton")
        self.horizontalLayout_19.addWidget(self.generateEdsButton)
        self.verifyEdsButton = QtWidgets.QPushButton(self.edsTab)
        self.verifyEdsButton.setObjectName("checkEdsButton")
        self.horizontalLayout_19.addWidget(self.verifyEdsButton)
        self.verticalLayout_16.addLayout(self.horizontalLayout_19)
        self.tabWidget.addTab(self.edsTab, "")
        self.verticalLayout.addWidget(self.tabWidget)
        main_window.setCentralWidget(self.centralwidget)

        self.retranslate_ui(main_window)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(main_window)
        main_window.setTabOrder(self.tabWidget, self.poybiusConvertedEditText)
        main_window.setTabOrder(self.poybiusConvertedEditText, self.polybiusOriginalTextEdit)

    def retranslate_ui(self, main_window: "UiMainWindow"):
        _translate = QtCore.QCoreApplication.translate
        main_window.setWindowTitle(_translate("MainWindow", "Опалева Е. Н.. ЛР 3. Вариант 1. Криптографические методы"))
        self.label_14.setText(_translate("MainWindow",
                                         "<html><head/><body><p><span style=\" font-weight:700;\">Задание: Расшифруйте</span></p></body></html>"))
        self.label_2.setText(_translate("MainWindow", "Исходный текст"))
        self.polybiusOriginalTextEdit.setHtml(_translate("MainWindow",
                                                         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                         "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                                         "p, li { white-space: pre-wrap; }\n"
                                                         "</style></head><body style=\" font-family:\'Segoe UI\'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">9758132013771526184942451321927715774920481548454827472394774816201317237996827747187725482723787727224814917722917723254817424510775418772325481742105547774948214648222018457747137747181877221344787721454815474877484713772144134113451377272248992248774827184792771645234948187977564822484677494815182047234521957742774948281845774920482792797758132013772146482220184513771846237715214518177717487722182577494820787749484413774847774718772144209145219577424177154217237977554713774147134513787727224877474244481617137714484592281877181648774718772315421742227977697715211877401877184377441341134548219278772722487718187721182017261877154822991548227720134148201518222195774822771648209508007700770054137721451817239429424377171847929777</span></p></body></html>"))
        self.label.setText(_translate("MainWindow", "Преобразованный текст"))
        self.label_3.setText(_translate("MainWindow", "Ключ"))
        self.textEdit.setHtml(_translate("MainWindow",
                                         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                         "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                         "p, li { white-space: pre-wrap; }\n"
                                         "</style></head><body style=\" font-family:\'Segoe UI\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ *, (, ), &lt;, &gt;, –, «, », …, № }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ !, ?, ;, а, б, в, г, д, е, ё }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ р, с, т, у, ф, х, ц, ч, ш, щ }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ У, Ф, Х, Ц, Ч, Ш, Щ, Ъ, Ы, Ь }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ ж, з, и, й, к, л, м, н, о, п }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ Й, К, Л, М, Н, О, П, Р, С, Т }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ А, Б, В, Г, Д, Е, Ё, Ж, З, И }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ 7, 8, 9, X, I, #, %,  , ,, . }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ Э, Ю, Я, 0, 1, 2, 3, 4, 5, 6 }</p>\n"
                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">{ ъ, ы, ь, э, ю, я, —, &quot;, :, - }</p></body></html>"))
        self.polybiusEncryptRadioButton.setText(_translate("MainWindow", "Зашифровать"))
        self.polybiusDecryptRadioButton.setText(_translate("MainWindow", "Расшифровать"))
        self.polybiusButton.setText(_translate("MainWindow", "Выполнить"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.polybiusTab), _translate("MainWindow", "Квадрат Полибия"))
        self.label_15.setText(_translate("MainWindow",
                                         "<html><head/><body><p><span style=\" font-weight:700;\">Задание: Выполните алгоритм шифрования ГОСТ 28147 89 в режиме имитовставки.</span></p></body></html>"))
        self.label_16.setText(_translate("MainWindow", "Ключ"))
        self.gostKeyLineEdit.setText(
            _translate("MainWindow", "45839695895184572594857967124356450966362023091609802819950324423807592810760"))
        self.label_17.setText(_translate("MainWindow", "Исходный текст"))
        self.gostOriginalTextEdit.setHtml(_translate("MainWindow",
                                                     "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                     "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                                     "p, li { white-space: pre-wrap; }\n"
                                                     "</style></head><body style=\" font-family:\'Segoe UI\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                                     "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"> великим книге, другой? нужно, что</p></body></html>"))
        self.label_19.setText(_translate("MainWindow", "Имитовставка"))
        self.label_18.setText(_translate("MainWindow", "Преобразованный текст"))
        self.gostEncryptRadioButton.setText(_translate("MainWindow", "Зашифровать"))
        self.gostDecryptRadioButton.setText(_translate("MainWindow", "Расшифровать"))
        self.gostButton.setText(_translate("MainWindow", "Выполнить"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.gost_28147_89_Tab),
                                  _translate("MainWindow", "ГОСТ 28147 89"))
        self.label_13.setText(_translate("MainWindow",
                                         "<html><head/><body><p><span style=\" font-weight:700;\">Задание: Сгенерируйте открытый и закрытый ключи в алгоритме шифрования RSA, используя простые числа p = 1229 и q = 1783. Зашифруйте следующее сообщение:</span></p></body></html>"))
        self.label_4.setText(_translate("MainWindow", "p:"))
        self.pLineEdit.setText(_translate("MainWindow", "1229"))
        self.label_5.setText(_translate("MainWindow", "q:"))
        self.qLineEdit.setText(_translate("MainWindow", "1783"))
        self.generateKeysButton.setText(_translate("MainWindow", "Сгенерировать ключи"))
        self.label_7.setText(_translate("MainWindow", "Публичный ключ"))
        self.label_6.setText(_translate("MainWindow", "Приватный ключ"))
        self.label_8.setText(_translate("MainWindow", "Ключ"))
        self.label_9.setText(_translate("MainWindow", "Исходный текст"))
        self.rsaOriginalTextEdit.setHtml(_translate("MainWindow",
                                                    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                    "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                                    "p, li { white-space: pre-wrap; }\n"
                                                    "</style></head><body style=\" font-family:\'Segoe UI\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                                    "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Веленью божию, о муза, будь послушна, Обиды не страшась, не требуя венца,</p></body></html>"))
        self.label_10.setText(_translate("MainWindow", "Преобразованный текст"))
        self.rsaEncryptRadioButton.setText(_translate("MainWindow", "Зашифровать"))
        self.rsaDecryptRadioButton.setText(_translate("MainWindow", "Расшифровать"))
        self.rsaButton.setText(_translate("MainWindow", "Выполнить"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.rsaTab), _translate("MainWindow", "RSA"))
        self.label_20.setText(_translate("MainWindow",
                                         "<html><head/><body><p><span style=\" font-weight:700;\">Реализовать алгоритм криптографической функции – Tiger. На входе сообщение произвольный длины. Размер хеша – 192 бит. Оценить быстродействие по сравнению с другими хэш-функциями, разработанными в тот период.</span></p></body></html>"))
        self.label_11.setText(_translate("MainWindow", "Исходный текст"))
        self.tigerOriginalTextEdit.setHtml(_translate("MainWindow",
                                                      "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                      "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                                      "p, li { white-space: pre-wrap; }\n"
                                                      "</style></head><body style=\" font-family:\'Segoe UI\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                                      "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Текст для хеширования</p></body></html>"))
        self.label_12.setText(_translate("MainWindow", "Хеш"))
        self.tigerButton.setText(_translate("MainWindow", "Выполнить"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tigerTab), _translate("MainWindow", "Tiger"))
        self.label_21.setText(_translate("MainWindow",
                                         "<html><head/><body><p><span style=\" font-weight:700;\">Используя хеш-образ своей Фамилии, вычислите электронную цифровую подпись по схеме RSA</span></p></body></html>"))
        self.label_22.setText(_translate("MainWindow", "Исходный текст"))
        self.edsOriginalTextEdit.setHtml(_translate("MainWindow",
                                                    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                    "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                                    "p, li { white-space: pre-wrap; }\n"
                                                    "</style></head><body style=\" font-family:\'Segoe UI\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                                    "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Опалева</p></body></html>"))
        self.label_23.setText(_translate("MainWindow", "Хеш"))
        self.label_24.setText(_translate("MainWindow", "Электронная цифровая подпись"))
        self.generateEdsButton.setText(_translate("MainWindow", "Сгененировать"))
        self.verifyEdsButton.setText(_translate("MainWindow", "Проверить на подлинность"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.edsTab), _translate("MainWindow", "ЭЦП"))
        self.label_25.setText(_translate("MainWindow", "Ключ: "))

    def setup_handlers(self):
        self.polybiusButton.clicked.connect(self.polybius_button_handler)
        self.gostButton.clicked.connect(self.gost_button_handler)
        self.tigerButton.clicked.connect(self.tiger_button_handler)
        self.generateKeysButton.clicked.connect(self.rsa_keys_button_handler)
        self.rsaButton.clicked.connect(self.rsa_button_handler)
        self.generateEdsButton.clicked.connect(self.generate_end_button_handler)
        self.verifyEdsButton.clicked.connect(self.verify_eds_button_handler)

    def show_warning(self, text: str, title: str = "Предупреждение"):
        QtWidgets.QMessageBox.warning(self, title, text)

    def show_info(self, text: str, title: str = "Информация"):
        QtWidgets.QMessageBox.information(self, title, text)

    def polybius_button_handler(self):
        is_encrypt = self.polybiusEncryptRadioButton.isChecked()
        try:
            if is_encrypt:
                # Шифруем исходный текст
                text = self.polybiusOriginalTextEdit.toPlainText()
                encrypt_text = polybius_square.encrypt(text)
                self.poybiusConvertedEditText.setText(encrypt_text)
            else:
                # Расшифровываем исходный текст
                encrypt_text = self.polybiusOriginalTextEdit.toPlainText()
                if not encrypt_text.isdigit():
                    self.show_warning("Текст должен состоять только из цифр [0-9]")
                    return

                decrypt_text = polybius_square.decrypt(encrypt_text)
                self.poybiusConvertedEditText.setText(decrypt_text)
        except exceptions.EncryptException as e:
            self.show_warning(str(e))
        except exceptions.DecryptException as e:
            self.show_warning(str(e))
        except Exception as e:
            self.show_warning("Возникла неизвестная ошибка")

    def gost_button_handler(self):
        key = self.gostKeyLineEdit.text()
        if not key.isdigit():
            self.show_warning("Ключ должен состоять только из цифр [0-9]")
            return

        key = int(key)
        is_encrypt = self.gostEncryptRadioButton.isChecked()
        try:
            if is_encrypt:
                # Шифруем исходный текст
                text = self.gostOriginalTextEdit.toPlainText()
                encrypt_text = gost_28147_89.encrypt(text, key)
                mac = gost_28147_89.mac(text, key)
                self.gostConvertedTextEdit.setText(encrypt_text)
                self.macLineEdit.setText(str(mac))
            else:
                # Расшифровываем исходный текст
                encrypt_text = self.gostOriginalTextEdit.toPlainText()
                if not encrypt_text.isdigit():
                    self.show_warning("Текст должен состоять только из цифр [0-9]")
                    return

                mac = encrypt_text[-10::]
                encrypt_text = encrypt_text[:-10]

                decrypt_text = gost_28147_89.decrypt(encrypt_text, key)
                self.gostConvertedTextEdit.setText(decrypt_text)

                is_valid = gost_28147_89.is_valid_text(decrypt_text, key, int(mac))
                if is_valid:
                    self.show_warning("Текст не изменен")
                else:
                    self.show_warning("Текст был изменен")

        except Exception as e:
            self.show_warning("Возникла неизвестная ошибка")

    def rsa_keys_button_handler(self):
        try:
            p = self.pLineEdit.text()
            if not p.isdigit() or not services.is_prime(int(p)):
                self.show_warning("p должно быть простое число!")
                return

            q = self.qLineEdit.text()
            if not q.isdigit() or not services.is_prime(int(q)):
                self.show_warning("q должно быть простое число!")
                return

            public_key, private_key = rsa.get_keys(int(p), int(q))
            self.publicKeyLineEdit.setText(f"{public_key[0]}, {public_key[-1]}")
            self.privateKeyLineEdit.setText(f"{private_key[0]}, {private_key[-1]}")
        except Exception as e:
            self.show_warning("Возникла неизвестная ошибка")

    def rsa_button_handler(self):
        key = self.rsaKeyLineEdit.text()
        key = list(map(str.strip, key.split(",")))
        if len(key) != 2 or not key[0].isdigit() or not key[1].isdigit():
            self.show_warning("Ключ должен быть в формате \"ЧИСЛО, ЧИСЛО\"")
            return

        is_encrypt = self.rsaEncryptRadioButton.isChecked()
        try:
            if is_encrypt:
                # Шифруем исходный текст
                text = self.rsaOriginalTextEdit.toPlainText()
                encrypt_text = rsa.encrypt(text, (int(key[0]), int(key[1])))
                self.rsaConvertedTextEdit.setText(encrypt_text)
            else:
                # Расшифровываем исходный текст
                encrypt_text = self.rsaOriginalTextEdit.toPlainText()
                # if not encrypt_text.isdigit():
                #     self.show_warning("Текст должен состоять только из цифр [0-9]")
                #     return

                decrypt_text = rsa.decrypt(encrypt_text, (int(key[0]), int(key[1])))
                self.rsaConvertedTextEdit.setText(decrypt_text)
        except Exception as e:
            self.show_warning("Возникла неизвестная ошибка")

    def tiger_button_handler(self):
        text = self.tigerOriginalTextEdit.toPlainText()
        try:
            hash_text = tiger.hash(text)
            self.tigerHashTextEdit.setText(hash_text)
        except Exception as e:
            self.show_warning("Возникла неизвестная ошибка")

    def generate_end_button_handler(self):
        key = self.edsKeyLineEdit.text()
        key = list(map(str.strip, key.split(",")))
        if len(key) != 2 or not key[0].isdigit() or not key[1].isdigit():
            self.show_warning("Ключ должен быть в формате \"ЧИСЛО, ЧИСЛО\"")
            return

        text = self.edsOriginalTextEdit.toPlainText()

        if not text:
            self.show_warning("Введите исходный текст!")
            return

        try:
            _hash = tiger.hash(text)
            self.edsHashTextEdit.setText(_hash)
            _eds = eds.generate_eds(text, (int(key[0]), int(key[1])))
            self.edsTextEdit.setText(_eds)
        except Exception as e:
            self.show_warning("Возникла неизвестная ошибка")

    def verify_eds_button_handler(self):
        key = self.edsKeyLineEdit.text()
        key = list(map(str.strip, key.split(",")))
        if len(key) != 2 or not key[0].isdigit() or not key[1].isdigit():
            self.show_warning("Ключ должен быть в формате \"ЧИСЛО, ЧИСЛО\"")
            return

        text = self.edsOriginalTextEdit.toPlainText()
        if not text:
            self.show_warning("Введите исходный текст!")
            return

        _eds = self.edsTextEdit.toPlainText()
        if not _eds.isdigit():
            self.show_warning("ЭЦП должна состоять только из цифр [0-9]")
            return
        try:
            if eds.verify_eds(text, _eds, (int(key[0]), int(key[1]))):
                self.show_info("ЭЦП подлинная")
            else:
                self.show_warning("ЭЦП не подлинная")
        except Exception as e:
            self.show_warning("Не верное указан ключ (используйте публичный ключ) или ЭЦП не подлинная")
