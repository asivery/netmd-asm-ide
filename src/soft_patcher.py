from PyQt5 import QtWidgets, uic, QtGui, QtQuick, QtCore

import fw_tools as fw_tl
from util import *
from dataclasses import dataclass

@dataclass
class SoftPatch:
    address: int
    value: int

@dataclass
class KnownPatch:
    name: str
    softPatch: SoftPatch

KNOWN_PATCHES = [
    KnownPatch("USB Buffer Code Execution CXD2680 V1.600 - part 1", SoftPatch(0x0000e69c, 0x08480047)),
    KnownPatch("USB Buffer Code Execution CXD2680 V1.600 - part 2", SoftPatch(0x0000e6c0, 0x74110002)),
    KnownPatch("USB Buffer Code Execution CXD2680 V1.600 - COMBO", SoftPatch(0x0000e69c, 0x13480047)),
    KnownPatch("Say 'NOPE' instead of 'HOLD' CXD2680 V1.600", SoftPatch(0x000863b9, 0x4e4f5045)),
    KnownPatch("Say 'WrP' instead of 'SAVED' CXD2680 V1.600", SoftPatch(0x00086450, 0x57725000)),
]

class SoftPatchWindow(QtWidgets.QDialog):
    def __init__(self, logCallback=None, toApply=None):
        super(SoftPatchWindow, self).__init__()
        uic.loadUi('softpatch.ui', self)
        self.templatesBox.addItem("----Select a predefined patch----")
        for patch in KNOWN_PATCHES:
            self.templatesBox.addItem(patch.name)
        self.templatesBox.currentIndexChanged.connect(lambda index: self._readjustKnownPatch(index))
        self.buttonBox.accepted.connect(self._accept)
        self.logCallback = logCallback
        self.setFixedSize(self.size())
        self.exec()

    def _accept(self):
        try:
            address = int(self.addressField.text(), 16)
            value = int(self.valueField.text(), 16)

            if len(hex(address)) > 10 or len(hex(value)) > 10:
                raise BaseException()
        except:
            self._log("Cannot parse parameters")
            return

        number = self.patchNumberField.value()

        try:
            device = fw_tl.connect()
            self._log(f"Patching address {hex(address)} with value {hex(value)} at #{number}")
            fw_tl.prep_auth(device)
            fw_tl.patch(device, address, value, number)
            self._log("Done!")
            self.accept()
        except BaseException as e:
            self._log("Error: " + messageOrPredef(e, "Couldn't connect to device!"))

    def _log(self, msg=""):
        msg = "[Soft-Patch]: " + msg
        if self.logCallback: self.logCallback(msg)
        print(msg)
    
    def _readjustKnownPatch(self, index):
        if index < 1:
            self.addressField.setText("")
            self.valueField.setText("")
            return
        self.addressField.setText(pad(hex(KNOWN_PATCHES[index - 1].softPatch.address)[2:], 8, '0'))
        self.valueField.setText(pad(hex(KNOWN_PATCHES[index - 1].softPatch.value)[2:], 8, '0'))
