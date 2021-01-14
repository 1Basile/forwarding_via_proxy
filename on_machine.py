#!/usr/bin/env python3
import socket
import time
from port_forwarder import Tunnel


HOST = '192.168.1.xxx'  # The server's hostname or IP address
PORT = 4444  # The port used by the server
PROTOCOLL_PORT = 7447

protocoll_port_dict = {'ssh': 22, 'telnet': 23, 'tftp': 69, 'http': 80, 'vnc': 5900}


def check_protocoll(ip, port):
    """Function receive information about with what port
    depend on protocoll to use establish connection."""
    protocol = 'ssh'        # default one
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((HOST, PROTOCOLL_PORT))
        protocol = conn.recv(1024).decode('ascii')
    except (OSError, ConnectionRefusedError):
        pass
    return protocol

def main():
    while True:
        protocoll = check_protocoll(HOST, PROTOCOLL_PORT)  # discovering what port to use
        protocoll_port = 22        # by default
        if protocoll and protocoll in protocoll_port_dict:
            protocoll_port = protocoll_port_dict[protocoll]


        Tunnel(HOST, PORT, '127.0.0.1', protocoll_port, 2, is_server=False).run()  # start tunneling
        time.sleep(4)


if __name__ == '__main__':
    main()
