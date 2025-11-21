import logging

from PyQt6 import QtWidgets

class PyQtGuiLoggingHandler(logging.Handler):

    def __init__(self, main_window: QtWidgets.QMainWindow):
        super().__init__()
        self.main_window = main_window

    def emit(self, record):
        text = self.format(record)
        if self.main_window and record.levelno >= logging.INFO:
            self.main_window.statusBar().showMessage(text, 5000)
        if record.levelno >= logging.ERROR:
            msg = QtWidgets.QMessageBox()
            msg.setIcon(QtWidgets.QMessageBox.Icon.Warning)
            msg.setWindowTitle("Error")
            msg.setText(text)
            msg.exec()
