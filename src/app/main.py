import sys

from PyQt6 import QtWidgets

from src.app import gui


def start():
    app = QtWidgets.QApplication(sys.argv)
    window = gui.UiMainWindow()
    window.show()
    app.exec()


if __name__ == "__main__":
    start()