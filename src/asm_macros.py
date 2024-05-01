"""
macros syntax:
$name value value value
This command will cause all further instances of <name> to be replaced with the value. Value may contain spaces

~name 
This command will undefine the <name> remap registered by $name ...

=reg
This command will set the temporary register used to hold the address of the function to call.

?func(arg1, arg2, arg3)
This command will execute the function at address `func`
args' format:
arg = ! - this register won't be touched
arg = *abc - abc will be loaded via an LDR instruction, and "abc" will be delegated somewhere in memory (as a word)
arg = *abc@ascii - abc will be loaded via an LDR instruction, and "abc" will be delegated somewhere in memory as an .ascii value
arg = *&abc - abc will be loaded via an ADR instruction, and "abc" will be delegated somewhere in memory
arg = &abc - abc will be loaded via an ADR instruction, "abc" won't be declared
arg = abc - abc will be loaded via a MOV.
"""
import random
import re

def split_ignore_delim_in_quotes(text: str, delimeter_char: str):
    text_buffer = ""
    in_quotes = False
    prev_c = None
    ret = []
    for c in text:
        if prev_c != '\\' and (c == '\'' or c == '"'):
            in_quotes = not in_quotes
        if not in_quotes and c == delimeter_char:
            ret.append(text_buffer)
            text_buffer = ""
            continue
        prev_c = c
        text_buffer += c
    return ret + [text_buffer]

def random_string(prefix: str, length: int) -> str:
    q = ""
    for _ in range(length):
        q += chr(random.randint(ord('A'), ord('Z')))
    return prefix + '_' + q

def process(input_lines: list[str]) -> list[str]:
    output_lines = []
    delegated_lines = ["\n", "\n"]
    remap_table = {}
    temporary_register = "r7"
    for line in input_lines:
        stripped = line.strip()

        # Process remap commands
        if stripped.startswith('$'):
            # remap table add entry
            name, val = stripped[1:].split(' ', 1)
            remap_table[name] = val
            continue
        elif stripped.startswith('~'):
            # remap table remove entry
            del remap_table[stripped[1:]]
            continue

        # Process remaps
        for f, t in remap_table.items(): line = line.replace(f, t)

        # Reload line after remaps
        stripped = line.strip()

        # Process comments
        if ';' in line:
            # Process the line char by char.
            in_quotes = False
            prev_char = None
            new_line = ""
            for char in line:
                if char == '\'' and prev_char != '\\':
                    in_quotes = not in_quotes
                if char == ';' and not in_quotes:
                    break # Start of a comment.
                prev_char = char
                new_line += char
            line = new_line
        if stripped.startswith('='):
            temporary_register = stripped[1:]
        elif stripped.startswith("?"):
            # invoke STDCALL function
            a = re.match(r'([^\(]*)\((.*)\)', stripped[1:])
            func_addr = a.group(1)
            args_str = a.group(2)

            for i, x in enumerate(split_ignore_delim_in_quotes(args_str, ',')):
                x = x.strip()
                if x == '!': continue # don't touch register
                elif x.startswith("*"): # load via an LDR
                    x = x[1:]
                    load_adr = False
                    if x.startswith("&"):
                        load_adr = True
                        x = x[1:]
                    v_type = "word"
                    if '@' in x:
                        v_type = x[x.rfind("@")+1:].strip()
                        x = x[:x.rfind("@")]
                    temp_name = random_string("arg", 12)
                    delegated_lines.append(f"{temp_name}: .{v_type} {x}")
                    output_lines.append(f"{'adr' if load_adr else 'ldr'} r{i}, {temp_name}")
                elif x.startswith("&"): # load via an ADR
                    output_lines.append(f"adr r{i}, {x[1:]}")
                else:
                    output_lines.append(f"mov r{i}, {x}")
            
            address_name = random_string("fptr", 10)
            delegated_lines.append(f"{address_name}: .word {func_addr}")
            output_lines.append(f"ldr {temporary_register}, {address_name}")
            return_label_name = random_string("fret", 10)
            output_lines.append(f"adr lr, {return_label_name}")
            output_lines.append(f"bx {temporary_register}")
            output_lines.append(f"{return_label_name}:")
        else:
            output_lines.append(line)
    return output_lines + delegated_lines

if __name__ == "__main__":
    with open("test.stdcall_asm", 'r') as e:
        for x in process(e.readlines()): print(x)
