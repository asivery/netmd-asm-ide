# A Patch IDE for Sony NetMD Portables

## About
This is a really basic Integrated Development Environment for Sony NetMD devices.
It allows you to create soft patches, write them to the device and execute raw code via a soft-patch.
I am not responsible for any damages done to your devices with the use of this program

### Soft Patches
Soft patches are volatile patches that can be written to the device, but disappear on reboot.
They provide a safe way of experimenting with the NetMD portables' firmware, without worrying about any
permanent damage. (As long as you're not messing with EEPROM code).

## Available soft patch presets
There are a few soft patch presets preloaded in the program, such as

|         **Name**          |                                    **Additional description**                                               |  **Compatibility** |
|---------------------------|-------------------------------------------------------------------------------------------------------------|--------------------|
| USB Buffer Code Execution | **Required** for this program to operate. It allows for executing the USB Buffer as raw code.               |   CXD2680 V1.600   |
| 'NOPE' instead of 'HOLD'  | Test patch written by @Sir68k in order to test soft patching.                                               |   CXD2680 V1.600   |
| 'WrP' instead of 'SAVED'  | Patch that changes the 'SAVED' message that pops up on the N510 and simmilar, to 'WrP' - write protected.   |   CXD2680 V1.600   |

## How to run any code on the Sony Portables?
This tool lets you easily compile and run assembly code on your NetMD portable.
In order to run any code you want, you first need to patch the device. Do that using the 'Soft Patch' menu.

The text field on the left contains the code, which will be assembled and sent to the device.
The text field on the right contains logs, and info about data sent and received from the device.

## Example code

A `Hello!` (World) program. It displays 'Hello!' on the device's internal display

```armasm
; The code below only works for devices based on
; the CXD2680 chip running FW 1.600
mov r0, 0x0
ldr r1, control
strb r0, [r1]

mov r0, 0x07
ldr r1, displayState
strb r0, [r1]

adr r0, localContents
ldr r1, systemBuffer
mov r2, 7
loop:
	ldrb r3, [r0]
	strb r3, [r1]
	add r0, r0, #1
	add r1, r1, #1
	subs r2, r2, #1
	bne loop
bx lr

displayState: .word 0x02000674
systemBuffer: .word 0x020007c8
control: .word 0x0200056c

localContents: .ascii "Hello!\0"
```

... or the same program written using _stdcall macros

```
; The code below only works for devices based on
; the CXD2680 chip running FW 1.600

$memcpy 0x0007cb19
$systemLCDBuffer 0x020007c8

push { lr }

mov r0, 0x0
ldr r1, control
strb r0, [r1]

mov r0, 0x07
ldr r1, displayState
strb r0, [r1]

?memcpy(*systemLCDBuffer, *&"Hello!\0\0"@ascii, 7);

pop { r0 }
bx r0

displayState: .word 0x02000674
control: .word 0x0200056c
```

## Contributions
Every contribution is welcome, if you'd like to improve something, please open a pull request!

## Credits
The code in `src/fw_tools.py` is an amalgamation of code from:

- [The Linux-Minidisc project](https://github.com/linux-minidisc/linux-minidisc)
- @Sir68k's soft patching prototype code
- [The Keystone Engine](https://www.keystone-engine.org)
