#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Tcp Port Forwarding (Reverse Proxy)


import socket
import threading
import logging
import sys


class Tunnel:
    """Class handle redirection from port local(_host, _port) to remote(_host, _port)."""
    def __init__(self, local_host, local_port, remote_host, remote_port, max_connection, is_server=True):
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s - %(levelname)s - %(message)s",
                            filename="port_forwarder.log")
        self.is_server = is_server
        self.server_socket, self.remote_socket = None, None
        self.server_socket, self.remote_socket = self.open_ports(local_host, local_port, remote_host, remote_port,
                                                                 max_connection)
        self.is_client_connected = False
        self.buffer = b''

    def open_ports(self, local_host, local_port, remote_host, remote_port, max_connection):
        """Method open sockets on local and remote on given ips and ports."""
        # connect to remote one
        try:
            logging.info("Trying to connect the point [%s:%d]" % (remote_host, remote_port))
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((remote_host, remote_port))
            logging.info("Connection established successfully.")
        except ConnectionRefusedError:
            logging.error("Connecting to server [%s:%d] refused." % (remote_host, remote_port))
            self.close_server()
            return None, None
        else:
            logging.info('Tunnel to redirect traffic between [%s:%d] and [%s:%d] established.'
                         % (local_host, local_port, remote_host, remote_port))
        # open local one
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.is_server:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((local_host, local_port))
            server_socket.listen(max_connection)
            logging.info('Server started at [%s:%d]' % (local_host, local_port))
        else:
            try:
                logging.info("Beginning of tunnel engineering..")
                logging.info("Trying to connect the point [%s:%d]" % (local_host, local_port))
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((local_host, local_port))
                logging.info("Connection established successfully.")
            except (ConnectionRefusedError, OSError):
                logging.error("Connecting to server [%s:%d] refused." % (local_host, local_port))
                self.close_server()
                return None, None
        return server_socket, remote_socket

    def transfer(self, recieve_sock, send_sock):
        while True:
            try:
                self.buffer = recieve_sock.recv(0x400)
            except (ConnectionResetError, OSError):
                self.buffer = b''

            if len(self.buffer) == 0:
                logging.warning("No data received! Breaking...")
                try:
                    #recieve_sock.shutdown(socket.SHUT_RDWR)
                    self.is_client_connected = False
                    recieve_sock.close()
                    logging.info("Closing connecions! [%s:%d]" % (recieve_sock.getsockname()))
                except OSError:
                   pass
                finally:
                    break

            try:
                send_sock.send(self.buffer)
            except OSError:
                logging.error("Sending ERROR. No address was supplied.")
                self.is_client_connected = False
                break


    def add_client(self):
        """Method detect client connection and accept it if it pass checking."""
        local_socket, local_address = self.server_socket.accept()
        logging.info('Detect connection from [%s:%s]' % (local_address[0], local_address[1]))
        self.is_client_connected = True
        return local_socket

    def run(self):
        """Method handle and support server live."""
        if not (self.server_socket or self.remote_socket):
            return
        if self.is_server:
            self.local_socket = self.add_client()
        else:
            self.local_socket = self.server_socket
        self.is_client_connected = True
        serv_queue = threading.Thread(target=self.transfer, args=(
            self.remote_socket, self.local_socket))
        remote_queue = threading.Thread(target=self.transfer, args=(
            self.local_socket, self.remote_socket))
        serv_queue.start()
        remote_queue.start()

        while True:
            if self.is_client_connected:
                continue
            else:
                self.close_server()
                break

    def close_server(self):
        """Is not implemented, yet."""
        logging.info("Closing connection to sockets!")
        logging.info("Releasing resources...")
        for sock in (self.server_socket, self.remote_socket):
            try:
                #sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except (AttributeError, OSError):
                pass
        logging.info("Tunnel shuted down!")


def main():
    if len(sys.argv) != 5:
        print("Usage : ")
        print("\tpython %s [L_HOST] [L_PORT] [R_HOST] [R_PORT]" % (sys.argv[0]))
        print("Example : ")
        print("\tpython %s 127.0.0.1 8888 127.0.0.1 22" % (sys.argv[0]))
        exit(1)
    LOCAL_HOST = sys.argv[1]
    LOCAL_PORT = int(sys.argv[2])
    REMOTE_HOST = sys.argv[3]
    REMOTE_PORT = int(sys.argv[4])
    MAX_CONNECTION = 0x10
    Tunnel(LOCAL_HOST, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT, MAX_CONNECTION)


if __name__ == "__main__":
    main()