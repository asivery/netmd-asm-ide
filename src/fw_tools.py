import usb1
import libusb1
import struct

MEM_TYPE_MAPPED     = 0
MEM_TYPE_EEPROM_32K = 2
MEM_TYPE_EEPROM_16K = 3

int_to_four_bytes = struct.Struct('<I').pack

_ord = ord
ord = lambda x: x if type(x) is int else _ord(x)

def calc_crc_byte(a, b):
    x = (a ^ b) & 0xffff

    for i in range(0x10):
        y = x & 0x8000
        x = (x << 0x11) >> 0x10
        if y != 0:
            x = (x ^ 0x1021) & 0xffff

    return x

def calc_crc(input, length):
    r = 0
    for i in range(length):
        r = calc_crc_byte(r, input[i])
    
    return (r & 0xFF, (r & 0xFF00) >> 8) 


def dump(data):
    if isinstance(data, basestring):
        result = ' '.join(['%02x' % (ord(x), ) for x in data])
    else:
        result = repr(data)
    return result


def prep_auth(md_iface):
    # 1. Open subunit desc
    md_iface.sendCommand([0x18,0x08,0x00,0x01,0x00])
    md_iface.readReply()

    # 2. Read subunit data
    md_iface.sendCommand([0x18,0x09,0x00,0xFF,0x00,0x00,0x00,0x00,0x00])
    md_iface.readReply()

    # 3. Close subunit desc
    md_iface.sendCommand([0x18,0x08,0x00,0x00,0x00])
    md_iface.readReply()

    # 4. Authenticate
    md_iface.sendCommand2([0x18,0x01,0xff,0x0e, 0x4e, 0x65, 0x74, 0x20, 0x4d, 0x44, 0x20, 0x57, 0x61, 0x6c, 0x6b, 0x6d, 0x61, 0x6e])
    md_iface.readReply2()

def read(md_iface, addr, mem_type, length=0x10):
    y1, y2, y3, y4 = int_to_four_bytes(addr & 0xFFFFFFFF)
    b4, b3, b2, b1 = ord(y1), ord(y2), ord(y3), ord(y4)

    # send open
    md_iface.sendCommand2([0x18,0x20,0xff,mem_type,b4,b3,b2,b1,length,0x01,0x00])
    md_iface.readReply2()

    # send read
    md_iface.sendCommand2([0x18,0x21,0xff,mem_type,b4,b3,b2,b1,length])
    reply = md_iface.readReply2()

    # send close
    md_iface.sendCommand2([0x18,0x20,0xff,mem_type,b4,b3,b2,b1,length,0x00,0x00])
    md_iface.readReply2()

    return [ord(x) for x in reply[11:(11+length)]]

def write(md_iface, addr, mem_type, data):
    y1, y2, y3, y4 = int_to_four_bytes(addr & 0xFFFFFFFF)
    b4, b3, b2, b1 = ord(y1), ord(y2), ord(y3), ord(y4)

    length = len(data)
    (crc_a, crc_b) = calc_crc(data, length)

    # send open
    md_iface.sendCommand2([0x18,0x20,0xff,mem_type,b4,b3,b2,b1,length,0x02,0x00])
    md_iface.readReply2()

    # send write
    md_iface.sendCommand2([0x18,0x22,0xff,mem_type,b4,b3,b2,b1,length,0x00,0x00] + data + [crc_a, crc_b])
    md_iface.readReply2()

    # send close
    md_iface.sendCommand2([0x18,0x20,0xff,mem_type,b4,b3,b2,b1,length,0x00,0x00])
    md_iface.readReply2()

def patch(md_iface, addr, val, patch_nr = 7):
    y1, y2, y3, y4 = int_to_four_bytes(addr & 0xFFFFFFFF)
    b4, b3, b2, b1 = ord(y1), ord(y2), ord(y3), ord(y4)

    y1, y2, y3, y4 = int_to_four_bytes(val & 0xFFFFFFFF)
    v1, v2, v3, v4 = ord(y1), ord(y2), ord(y3), ord(y4)

    base    = 0x03802000 + patch_nr * 0x10
    control = 0x03802080

    # write 5, 12 to main control
    write(md_iface, control, MEM_TYPE_MAPPED, [5])
    write(md_iface, control, MEM_TYPE_MAPPED, [12])

    # AND 0xFE with patch control
    patch_ctl = read(md_iface, base, MEM_TYPE_MAPPED, 4)
    patch_ctl[0] = patch_ctl[0] & 0xFE
    write(md_iface, base, MEM_TYPE_MAPPED, patch_ctl)

    # AND 0xFD with patch control
    patch_ctl = read(md_iface, base, MEM_TYPE_MAPPED, 4)
    patch_ctl[0] = patch_ctl[0] & 0xFD
    write(md_iface, base, MEM_TYPE_MAPPED, patch_ctl)

    # write patch addr
    write(md_iface, base + 4, MEM_TYPE_MAPPED, [b4, b3, b2, b1])
    # write path val
    write(md_iface, base + 8, MEM_TYPE_MAPPED, [v4, v3, v2, v1])

    # OR 1 with patch control
    patch_ctl = read(md_iface, base, MEM_TYPE_MAPPED, 4)
    patch_ctl[0] = patch_ctl[0] | 1
    write(md_iface, base, MEM_TYPE_MAPPED, patch_ctl)

    # write 5, 9 to main control
    write(md_iface, control, MEM_TYPE_MAPPED, [5])
    write(md_iface, control, MEM_TYPE_MAPPED, [9])

def execute(md, code):
    md.sendCommand(md.formatQuery("18d2ff %*", code))
    return md.net_md.readReply()

KNOWN_USB_ID_SET = frozenset([
    (0x04dd, 0x7202), # Sharp IM-MT899H
    (0x054c, 0x0075), # Sony MZ-N1 
    (0x054c, 0x0080), # Sony LAM-1 
    (0x054c, 0x0081), # Sony MDS-JB980 
    (0x054c, 0x0084), # Sony MZ-N505 
    (0x054c, 0x0085), # Sony MZ-S1 
    (0x054c, 0x0086), # Sony MZ-N707 
    (0x054c, 0x00c6), # Sony MZ-N10 
    (0x054c, 0x00c7), # Sony MZ-N910
    (0x054c, 0x00c8), # Sony MZ-N710/NF810 
    (0x054c, 0x00c9), # Sony MZ-N510/N610 
    (0x054c, 0x00ca), # Sony MZ-NE410/NF520D 
    (0x054c, 0x00eb), # Sony MZ-NE810/NE910
    (0x054c, 0x0101), # Sony LAM-10
    (0x054c, 0x0113), # Aiwa AM-NX1
    (0x054c, 0x014c), # Aiwa AM-NX9
    (0x054c, 0x017e), # Sony MZ-NH1
    (0x054c, 0x0180), # Sony MZ-NH3D
    (0x054c, 0x0182), # Sony MZ-NH900
    (0x054c, 0x0184), # Sony MZ-NH700/NH800
    (0x054c, 0x0186), # Sony MZ-NH600/NH600D
    (0x054c, 0x0188), # Sony MZ-N920
    (0x054c, 0x018a), # Sony LAM-3
    (0x054c, 0x01e9), # Sony MZ-DH10P
    (0x054c, 0x0219), # Sony MZ-RH10
    (0x054c, 0x021b), # Sony MZ-RH710/MZ-RH910/MZ-M10
    (0x054c, 0x022c), # Sony CMT-AH10 (stereo set with integrated MD)
    (0x054c, 0x023c), # Sony DS-HMD1 (device without analog music rec/playback)
    (0x054c, 0x0286), # Sony MZ-RH1
])


_FORMAT_TYPE_LEN_DICT = {
    'b': 1, # byte
    'w': 2, # word
    'd': 4, # doubleword
    'q': 8, # quadword
}
STATUS_CONTROL = 0x00
STATUS_STATUS = 0x01
STATUS_SPECIFIC_INQUIRY = 0x02
STATUS_NOTIFY = 0x03
STATUS_GENERAL_INQUIRY = 0x04
# ... (first byte of response)
STATUS_NOT_IMPLEMENTED = 0x08
STATUS_ACCEPTED = 0x09
STATUS_REJECTED = 0x0a
STATUS_IN_TRANSITION = 0x0b
STATUS_IMPLEMENTED = 0x0c
STATUS_CHANGED = 0x0d
STATUS_INTERIM = 0x0f


def iterdevices(usb_context, bus=None, device_address=None):
    """
      Iterator for plugged-in NetMD devices.

      Parameters:
        usb_context (usb1.LibUSBContext)
          Some usb1.LibUSBContext instance.
        bus (None, int)
          Only scan this bus.
        device_address (None, int)
          Only scan devices at this address on each scanned bus.

      Returns (yields) NetMD instances.
    """
    for device in usb_context.getDeviceList():
        if bus is not None and bus != device.getBusNumber():
            continue
        if device_address is not None and \
           device_address != device.getDeviceAddress():
            continue
        if (device.getVendorID(), device.getProductID()) in KNOWN_USB_ID_SET:
            yield NetMD(device.open())


def connect():
    context = usb1.LibUSBContext()
    device = list(iterdevices(context))[0]
    return NetMDInterface(device)

class NetMD(object):
    """
      Low-level interface for a NetMD device.
    """
    def __init__(self, usb_handle, interface=0):
        """
          usb_handle (usb1.USBDeviceHandle)
            USB device corresponding to a NetMD player.
          interface (int)
            USB interface implementing NetMD protocol on the USB device.
        """
        self.usb_handle = usb_handle
        self.interface = interface
        usb_handle.setConfiguration(1)
        usb_handle.claimInterface(interface)
        if self._getReplyLength() != 0:
            self.readReply()


    def __del__(self):
        try:
            self.usb_handle.resetDevice()
            self.usb_handle.releaseInterface(self.interface)
        except: # Should specify an usb exception
            pass

    def _getReplyLength(self):
        reply = self.usb_handle.controlRead(libusb1.LIBUSB_TYPE_VENDOR | \
                                            libusb1.LIBUSB_RECIPIENT_INTERFACE,
                                            0x01, 0, 0, 4)
        return reply[2]

    def sendCommand(self, command):
        """
          Send a raw binary command to device.
          command (str)
            Binary command to send.
        """
        #print '%04i> %s' % (len(command), dump(command))
        self.usb_handle.controlWrite(libusb1.LIBUSB_TYPE_VENDOR | \
                                     libusb1.LIBUSB_RECIPIENT_INTERFACE,
                                     0x80, 0, 0, command) #0x80, 0, 0, command

    def sendCommand2(self, command):
        """
          Send a raw binary command to device.
          command (str)
            Binary command to send.
        """
        #print '%04i> %s' % (len(command), dump(command))
        self.usb_handle.controlWrite(libusb1.LIBUSB_TYPE_VENDOR | \
                                     libusb1.LIBUSB_RECIPIENT_INTERFACE,
                                     0xff, 0, 0, command) #0x80, 0, 0, command

    def readReply(self):
        """
          Get a raw binary reply from device.
          Returns the reply.
        """
        reply_length = 0
        while reply_length == 0:
            reply_length = self._getReplyLength()
            if reply_length == 0: sleep(0.1)
        reply = self.usb_handle.controlRead(libusb1.LIBUSB_TYPE_VENDOR | \
                                            libusb1.LIBUSB_RECIPIENT_INTERFACE,
                                            0x81, 0, 0, reply_length) #0x81
        #print '%04i< %s' % (len(reply), dump(reply))
        return reply

    def readReply2(self):
        """
          Get a raw binary reply from device.
          Returns the reply.
        """
        reply_length = 0
        while reply_length == 0:
            reply_length = self._getReplyLength()
            if reply_length == 0: sleep(0.1)
        reply = self.usb_handle.controlRead(libusb1.LIBUSB_TYPE_VENDOR | \
                                            libusb1.LIBUSB_RECIPIENT_INTERFACE,
                                            0xff, 0, 0, reply_length) #0x81
        #print '%04i< %s' % (len(reply), dump(reply))
        return reply


    def readBulk(self, length):
        """
          Read bulk data from device.
          length (int)
            Length of data to read.
          Returns data read.
        """
        result = StringIO()
        self.readBulkToFile(length, result)
        return result.getvalue()

    def readBulkToFile(self, length, outfile, chunk_size=0x10000, callback=lambda: None):
        """
          Read bulk data from device, and write it to a file.
          length (int)
            Length of data to read.
          outfile (str)
            Path to output file.
          chunk_size (int)
            Keep this much data in memory before flushing it to file.
        """
        done = 0
        while done < length:
            received = self.usb_handle.bulkRead(BULK_READ_ENDPOINT,
                min((length - done), chunk_size))
            done += len(received)
            outfile.write(received)
            callback(done)

    def writeBulk(self, data):
        """
          Write data to device.
          data (str)
            Data to write.
        """
        self.usb_handle.bulkWrite(BULK_WRITE_ENDPOINT, data)


class NetMDInterface(object):
    """
      High-level interface for a NetMD device.
      Notes:
        Track numbering starts at 0.
        First song position is 0:0:0'1 (0 hours, 0 minutes, 0 second, 1 sample)
        wchar titles are probably shift-jis encoded (hint only, nothing relies
          on this in this file)
    """
    def __init__(self, net_md):
        """
          net_md (NetMD)
            Interface to the NetMD device to use.
        """
        self.net_md = net_md

    def send_query(self, query, test=False):
        # XXX: to be removed (replaced by 2 separate calls)
        self.sendCommand(query, test=test)
        return self.readReply()

    def sendCommand(self, query, test=False, factory=False):
        if test:
            query = [STATUS_SPECIFIC_INQUIRY, ] + query
        else:
            query = [STATUS_CONTROL, ] + query
        binquery = bytes(query)
        if not factory: self.net_md.sendCommand(binquery)
        else: self.net_md.sendCommand2(binquery)

    def sendCommand2(self, query, test=False):
        self.sendCommand(query, test, True)

    def readReply2(self):
        return self.readReply(True)

    def readReply(self, factory=False):
        result = self.net_md.readReply() if not factory else self.net_md.readReply2()
        status = ord(result[0])
        if status == STATUS_NOT_IMPLEMENTED:
            raise BaseException('Not implemented')
        elif status == STATUS_REJECTED:
            raise BaseException('Rejected')
        elif status not in (STATUS_ACCEPTED, STATUS_IMPLEMENTED,
                            STATUS_INTERIM):
            raise BaseException('Unknown returned status: %02X' %
                (status, ))
        return result[1:]

    def formatQuery(self, format, *args):
        print("Send>>>" + format)
        ord_ = lambda x: x if type(x) is int else ord(x)
        result = []
        append = result.append
        extend = result.extend
        half = None
        def hexAppend(value):
            append(int(value, 16))
        escaped = False
        arg_stack = list(args)
        for char in format:
            if escaped:
                escaped = False
                value = arg_stack.pop(0)
                if char in _FORMAT_TYPE_LEN_DICT:
                    for byte in xrange(_FORMAT_TYPE_LEN_DICT[char] - 1, -1, -1):
                        append((value >> (byte * 8)) & 0xff)
                # String ('s' is 0-terminated, 'x' is not)
                elif char in ('s', 'x'):
                    length = len(value)
                    if char == 's':
                        length += 1
                    append((length >> 8) & 0xff)
                    append(length & 0xff)
                    extend(ord_(x) for x in value)
                    if char == 's':
                        append(0)
                elif char == '*':
                    extend(ord_(x) for x in value)
                else:
                    raise ValueError('Unrecognised format char: %r' % (char, ))
                continue
            if char == '%':
                assert half is None
                escaped = True
                continue
            if char == ' ':
                continue
            if half is None:
                half = char
            else:
                hexAppend(half + char)
                half = None
        assert len(arg_stack) == 0
        return result

    def scanQuery(self, query, format):
        result = []
        append = result.append
        half = None
        escaped = False
        
        e = lambda x: (max(0, 4-len(hex(ord(x)))) * '0') + hex(ord(x))[2:]
        dbgrsta = list(''.join([e(x) for x in query]))
        n = format.find(' ')
        while n != -1:
            dbgrsta.insert(n, ' ')
            n = format.find(' ', n+1)
        
        print("-----------------------\nFMT: %s\nSTA: %s\n-----------------------" % (format, ''.join(dbgrsta)))
        
        input_stack = list(query)
        def pop():
            return ord(input_stack.pop(0))
        for char in format:
            if escaped:
                escaped = False
                if char == '?':
                    pop()
                    continue
                if char in _FORMAT_TYPE_LEN_DICT:
                    value = 0
                    for byte in xrange(_FORMAT_TYPE_LEN_DICT[char] - 1, -1, -1):
                        value |= (pop() << (byte * 8))
                    append(value)
                # String ('s' is 0-terminated, 'x' is not)
                elif char in ('s', 'x'):
                    length = pop() << 8 | pop()
                    value = ''.join(input_stack[:length])
                    input_stack = input_stack[length:]
                    if char == 's':
                        append(value[:-1])
                    else:
                        append(value)
                # Fetch the remainder of the query in one value
                elif char == '*':
                    value = ''.join(input_stack)
                    input_stack = []
                    append(value)
                else:
                    raise ValueError('Unrecognised format char: %r' % (char, ))
                continue
            if char == '%':
                #assert half is None
                escaped = True
                continue
            if char == ' ':
                continue
            if half is None:
                half = char
            else:
                input_value = pop()
                format_value = int(half + char, 16)
                if format_value != input_value:
                    raise ValueError('Format and input mismatch at %i: '
                        'expected %02x, got %02x' % (
                            len(query) - len(input_stack) - 1,
                            format_value, input_value))
                half = None
        assert len(input_stack) == 0
        return result
