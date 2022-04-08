from PyQt5 import QtWidgets

def warn(str):
    QtWidgets.QMessageBox(text=str).exec()

def hexify(bts):
    return ''.join(('0' if x < 0x10 else '') + hex(x)[2:] for x in bts) if bts else '<NONE>'

def pad(str, length, char):
    strlen = len(str)
    return str if strlen >= length else ((char * (length - strlen)) + str)

def messageOrPredef(ex, predefined):
    return ex.message if hasattr(ex, 'message') else predefined
