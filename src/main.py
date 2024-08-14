from PyQt5 import QtWidgets, uic, QtGui, QtQuick, QtCore
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

import sys
import signal

import fw_tools as fw_tl
from util import *
from soft_patcher import SoftPatchWindow
from asm_macros import process as process_macros

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
        rawinput = self.inputEdit.toPlainText()
        program = '\n'.join(process_macros(rawinput.split("\n")))
        engine = Ks(KS_ARCH_ARM, KS_MODE_ARM if not self.useThumbCheckBox.isChecked() else KS_MODE_THUMB)
        try:
            assembled, length = engine.asm(program)
        except BaseException as e:
            self._log(e.message)
            return
        
        self._log("--------------------------------------------")
        self._log(f"Assembled! The code is {length} instructions long")
        self._log(f"Raw assembled chunk: ")
        self._log(hexify(assembled))
        return assembled, length

    def _runAction(self):
        commandLines = [x.strip()[2:] for x in self.inputEdit.toPlainText().split("\n") if x.strip().startswith(";@")]
        justTransfer = False
        highRamAddress = 0x02006000
        hexContent = None
        for line in commandLines:
            tokens = line.split(" ")
            if tokens[0] == "HIRAM":
                highRamAddress = int(tokens[1], 16)
            elif tokens[0] == "RAW":
                hexContent = [int(tokens[1][i:i+2], 16) for i in range(0, len(tokens[1]), 2)]
            elif tokens[0] == "LOADONLY":
                justTransfer = True
            else:
                self._log(f"Invalid parser command: {tokens[0]}")
                return

        if not hexContent:
            assembled, length = self._compile()
        else:
            assembled, length = hexContent, len(hexContent)
            self._log("Sending just the raw data. No code was assembled")
            self._log(f"Data to send is {hexify(assembled)}")

        if not assembled:
            self._log("Invalid assembly code. Nothing has been sent to device")
            return

        self._log()
        self._log("Sending to device...")
        if justTransfer:
            self._log(f"Instructed to just transfer the data to RAM, and not run it. Copying code to {hex(highRamAddress)}")
            try:
                device = fw_tl.connect()
                fw_tl.prep_auth(device)
                fw_tl.writeAbstractLength(device, highRamAddress, fw_tl.MEM_TYPE_MAPPED, assembled)
                device.net_md.__del__()
                self._log("Transfer completed successfully")
            except BaseException as e:
                self._log("Error: " + messageOrPredef(e, "Cannot connect to device!")) 
        else:
            if len(assembled) > 500:
                self._log("As the code is larger than 500 bytes, it will be written to high RAM first. This will make it impossible to read out the response from the response USB buffer.")
                self._log(f"High RAM is defined as {highRamAddress}")
                try:
                    device = fw_tl.connect()
                    fw_tl.prep_auth(device)
                    fw_tl.writeAbstractLength(device, highRamAddress, fw_tl.MEM_TYPE_MAPPED, assembled)
                    self._log("Code transferred successfully. Executing jump code")
                    engine = Ks(KS_ARCH_ARM, KS_MODE_ARM)
                    asm, _ = engine.asm(f"""
ldr r0, highRAM
bx r0
highRAM:
    .word {highRamAddress}
                    """)
                    fw_tl.execute(device, asm)
                    device.net_md.__del__()
                except BaseException as e:
                    self._log("Error: " + messageOrPredef(e, "Cannot connect to device!")) 
                return
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
