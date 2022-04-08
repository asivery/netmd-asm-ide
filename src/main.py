from PyQt5 import QtWidgets, uic, QtGui, QtQuick, QtCore
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

import sys
import signal

import fw_tools as fw_tl
from util import *
from soft_patcher import SoftPatchWindow


class AsmMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(AsmMainWindow, self).__init__() 
        uic.loadUi('main.ui', self)

        self.saveButton.clicked.connect(lambda: self._saveAction())
        self.loadButton.clicked.connect(lambda: self._loadAction())
        self.runButton.clicked.connect(lambda: self._runAction())
        self.justCompileButton.clicked.connect(lambda: self._compile())
        self.softPatchButton.clicked.connect(lambda: self._softPatchAction())
        self.saveLogsButton.clicked.connect(lambda: self._saveLogsAction())
        self.inputEdit.setTabStopWidth(20)

        self.compileShortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+Return"), self)
        self.compileShortcut.activated.connect(lambda: self._compile())
        self.runShortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+Shift+Return"), self)
        self.runShortcut.activated.connect(lambda: self._runAction())


        self.show()

    def _saveAction(self):
        file = QtWidgets.QFileDialog.getSaveFileName(self, "Save ASM", filter="ASM File (*.asm, *.S)")[0]
        if not len(file): return False
        with open(file, 'w') as e:
            e.write(self.inputEdit.toPlainText())
            warn("Saved")

    def _saveLogsAction(self):
        file = QtWidgets.QFileDialog.getSaveFileName(self, "Save ASM", filter="ASM File (*.asm, *.S)")[0]
        if not len(file): return False
        with open(file, 'w') as e:
            e.write(self.programOutput.toPlainText())
            warn("Saved")
    

    
    def _loadAction(self):
        file = QtWidgets.QFileDialog.getOpenFileName(self, "Load ASM", filter="ASM File (*.asm, *.S)")[0]
        if not len(file): return False
        with open(file, 'r') as e:
            self.inputEdit.setPlainText(e.read())
            warn("Loaded")

    def _log(self, message=''):
        self.programOutput.setPlainText(self.programOutput.toPlainText() + message + "\n")
        self.programOutput.verticalScrollBar().setValue(self.programOutput.verticalScrollBar().maximum())


    def _softPatchAction(self):
        SoftPatchWindow(lambda msg: self._log(msg))

    def _compile(self):
        program = self.inputEdit.toPlainText()
        program = '\n'.join(x if ';' not in x else x[:x.find(';')] for x in program.split("\n"))
        engine = Ks(KS_ARCH_ARM, KS_MODE_ARM if not self.useThumbCheckBox.isChecked() else KS_MODE_THUMB)
        try:
            assembled, length = engine.asm(program)
        except Exception as e:
            self._log(e.message)
            return
        
        self._log("--------------------------------------------")
        self._log(f"Assembled! The code is {length} instructions long")
        self._log(f"Raw assembled chunk: ")
        self._log(hexify(assembled))
        return assembled, length

    def _runAction(self):
        assembled, length = self._compile()
        if not assembled:
            self._log("Invalid assembly code. Nothing has been sent to device")
            return

        self._log()
        self._log("Sending to device...")
        try:
            device = fw_tl.connect()
            response = fw_tl.execute(device, assembled)[4:]
            self._log(f"USB Buffer is {len(response)} bytes long")
            self._log(f"Raw data: ")
            self._log(hexify(response))
            self._log()
            device.net_md.__del__()
        except BaseException as e:
            self._log("Error: " + messageOrPredef(e, "Cannot connect to device!")) 


    
def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = QtWidgets.QApplication(sys.argv)
    AsmMainWindow()
    app.exec_()

if __name__ == "__main__":
    main()
