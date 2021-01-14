"""Script try to connect to server using ssh protocol. """
import os
import socket
import selectors
import types
import logging
import hashlib


class Redirection:
    """Class that generalize all actions with ssh connection."""

    def __init__(self, host_ip, redirection_port, cmd_port, wake_up_port, active_protocol_port, rm_pcs_ip_check_port,
                 number_of_tries=3, default_protocol='ssh', protocols_available=('ssh', 'telnet', 'vnc'),
                 settings_from_file=False):

        if settings_from_file:  # read setting from settings file
            self.__hidden_init(**self.settings_reader("proxy_settings"))
        else:
            self.__hidden_init(host_ip, redirection_port, cmd_port, wake_up_port, active_protocol_port,
                               rm_pcs_ip_check_port,
                               number_of_tries, default_protocol, protocols_available)

    def __hidden_init(self, host_ip, redirection_port, cmd_port, wake_up_port, active_protocol_port,
                      rm_pcs_ip_check_port,
                      cmd_passwd_number_of_tries, default_protocol, protocols_available):
        """Function initialize proxy."""
        self.redirection_port = None
        self.selector = selectors.DefaultSelector()
        self.session = None
        self.remote_pc = None
        self.conn_rm_machines = {}  # {(ip, port): socket}
        self.rm_pc_ips = ('192.168.1.xxx',)
        self.client = None
        self.conn_clients = {}
        self.unauth_cmd_conn = {}
        self.verf_cmd_conn = None
        self.host = host_ip
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s - %(levelname)s - %(message)s", filename='proxy.log')
        self.redirection_port = self.open_port(redirection_port)
        self.redirection_port_n = redirection_port
        logging.info('Server started at [%s:%d]' % (host_ip, redirection_port))  # file with settings

        self.cmd_port = self.open_port(cmd_port)
        self.cmd_port_n = cmd_port

        logging.info('Server cmd at [%s:%d]' % (host_ip, cmd_port))  # vnc server
        # passwd, salt
        self.__cmd_password_hash = (b'[;\x95\xb8c\xa9NQs\xe45K\x8e\xb6\xdcXFZq\xab\x9f\xf4\x1cb\xb2\x03&J\x80\xe2x\xfc',
                                    b'3\x15\x18J\x96!\x08\x92\xb1qH\xb4\x7f\x9c^QF^7e\xaf\x8eP9\x1b7{[r:\x0e\x05')
        self.number_of_tries = cmd_passwd_number_of_tries

        self.buffers = {}  # conn: buffer

        self.wake_up_port = self.open_port(wake_up_port)
        self.wake_up_port_n = wake_up_port
        self.need_to_wake_up = ''

        self.active_protocol = default_protocol  # default one
        self.protocols_available = protocols_available
        logging.info(f"Current transmission protocol is {self.active_protocol}.")
        self.protocol_port = self.open_port(active_protocol_port)
        self.protocol_port_n = active_protocol_port

        self.rm_pcs_ip_check_port = self.open_port(rm_pcs_ip_check_port)
        self.rm_pcs_ip_check_port_n = rm_pcs_ip_check_port

    @staticmethod
    def settings_reader(settings_file):
        """Method read all settings information for proxy to work properly."""
        with open(settings_file, 'r') as f:
            settings_file = f.readlines()
            settings = tuple(i.lstrip("#").strip(" ").rstrip("\n") for i in settings_file if i.startswith("# "))
            if len(settings) != 9:
                logging.error("Wrong settings in settings file.")
            else:
                dict_ = {}
                for setting in settings:
                    key, value = setting.split("=", maxsplit=1)

                    if value.strip(" ").isdigit():
                        value = int(value.strip(" "))
                    else:
                        value = value.strip(" ")

                    dict_.update({key.strip(" "): value})
                dict_["protocols_available"] = dict_["protocols_available"][1:-1].split(',')
        return dict_

    def open_port(self, port):
        """Method open port to listen."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.host, port))
        except OSError:
            logging.error("Address [%s:%d] already in use" % (self.host, port))
        sock.listen()
        sock.setblocking(False)
        # logging
        self.selector.register(sock, selectors.EVENT_READ, data=None)
        return sock

    def wake_up_interaction(self, sock):
        """
        Method check whether pc need to booted, if so
        send it WOL packet and remember, that pc is already booted.
        """
        if self.need_to_wake_up:
            sock.send(f'{self.need_to_wake_up}'.encode('ASCII'))
            self.need_to_wake_up = ''
            logging.info("Wake up signall have been sent.")

    def rm_pcs_ip_change(self, sock):
        """Function receive ip, from what rm pc will be connected."""
        try:
            ip = sock.recv(1024).decode("ascii")
            if set(ip).difference(set([f"{i}" for i in range(10)])) == {"."}:
                self.rm_pc_ips = [ip, ]
        except BaseException as err:
            logging.error(err)

    def add_client(self, sock):
        """Function accept client connection and register it in selector."""
        conn, addr = sock.accept()
        conn.setblocking(False)

        if sock == self.cmd_port:
            # give client some information, to what they have been connected
            # and ask them to enter password
            conn.send(f"Welcome at proxy command line interface.{os.linesep}{os.linesep}".encode('utf-8'))
            conn.send(f"proxy@{self.host}`s password: ".encode('utf-8'))
            logging.info("Accepted non-authorized connection from [%s:%d] to CMD port" % conn.getpeername())
            data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
            self.selector.register(conn, events, data=data)
            self.unauth_cmd_conn.update({conn: 0})  # {Connection: number of tries to get in.}
            self.buffers.update({conn: b''})

        elif sock == self.wake_up_port:  # If need to wake up pc
            self.wake_up_interaction(conn)
            conn.close()

        elif sock == self.protocol_port:
            conn.send(f'{self.active_protocol}'.encode('ASCII'))  # protocol to use
            logging.info("Active protocol to use have been sent.")
            conn.close()

        elif sock == self.rm_pcs_ip_check_port:
            self.rm_pcs_ip_change(conn)
            conn.close()

        elif sock == self.redirection_port:
            conn.setblocking(False)
            data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
            self.selector.register(conn, events, data=data)
            self.buffers.update({conn: b''})
            if addr[0] in self.rm_pc_ips:
                if not self.remote_pc:
                    self.remote_pc = conn
                    logging.info("Accepted connection from [%s:%d] as remote pc." % conn.getpeername())
                else:
                    logging.info("Accepted connection from [%s:%d] as unactive remote pc." % conn.getpeername())
                    self.conn_rm_machines.update({addr: conn})

            elif not self.client:
                self.client = conn
                self.need_to_wake_up = 'my pc'
                # self.conn_clients.update({conn.getpeername(): conn})
                logging.info("Accepted connection from [%s:%d] as client." % conn.getpeername())
            else:
                self.conn_clients.update({conn.getpeername(): conn})
                logging.info("Accepted connection from [%s:%d] as unactive client." % conn.getpeername())

    def close_client(self, sock):
        """Function close client connection and unregister it in selector."""
        try:
            logging.info("Closing connecion to [%s:%d]" % sock.getpeername())
        except OSError:
            logging.info("Closing connecion to rm pc.")
        if self.client == sock:
            self.client = None
        elif self.remote_pc == sock:
            try:
                sock.send("reboot".encode('utf-8'))
            except OSError:
                pass
            self.remote_pc = None
        elif self.verf_cmd_conn == sock:
            self.verf_cmd_conn = None
        elif sock in self.conn_clients.values():
            self.conn_clients.pop(sock.getpeername())  # {("ip", port): sock}
        elif sock in self.conn_rm_machines.values():
            self.conn_rm_machines.pop(sock.getpeername())  # {("ip", port): sock}
        elif sock in self.unauth_cmd_conn:
            self.unauth_cmd_conn.pop(sock)  # (sock: number of tries)
        self.selector.unregister(sock)
        sock.close()

    def read_to_buffer(self, sock, mask):
        """Method read information from to buffer"""
        if mask & selectors.EVENT_READ:
            try:
                recv_data = sock.recv(1024)
                if recv_data:
                    self.buffers[sock] += recv_data.replace(b'\r', b'')
                else:
                    logging.warning("No data received! Breaking...")
                    self.close_client(sock)
            except ConnectionResetError:
                self.close_client(sock)

    def read_from_buffer(self, sock, by_lines=True):
        """Method tries to read line from socket(if line is finished) buffer."""
        if by_lines:
            if b"\n" in self.buffers[sock]:
                recv_line, self.buffers[sock] = self.buffers[sock].split(b"\n", maxsplit=1)
                return recv_line
        else:
            bytes_send = 1024
            recv_line, self.buffers[sock] = self.buffers[sock][:bytes_send], self.buffers[sock][bytes_send:]
            return recv_line

    def redirect_inf(self, key, mask):
        """Method redirect inf from one client to another."""
        recv_sock = key.fileobj
        data = key.data

        if recv_sock == self.client:
            send_sock = self.remote_pc
        else:  # recv_sock == self.remote_pc
            send_sock = self.client

        if mask & selectors.EVENT_READ:
            try:
                recv_data = recv_sock.recv(1024)  # Should be ready to read
            except ConnectionResetError:
                recv_data = b''
            if recv_data:
                data.outb += recv_data
            else:
                logging.warning("No data received! Breaking...")
                self.close_client(recv_sock)
                self.close_client(send_sock)
        if mask & selectors.EVENT_WRITE:
            if data.outb:
                sent = send_sock.send(data.outb)  # Should be ready to write
                data.outb = data.outb[sent:]

    def auth_cmd_conn(self, key, mask):
        """Method check whether connection send right password."""
        sock = key.fileobj
        data = key.data
        recv_line = self.read_from_buffer(sock)
        if recv_line:
            if recv_line == bytes(os.linesep, encoding='utf-8'):
                return
            passwd = hashlib.pbkdf2_hmac(
                'sha256',  # The hash digest algorithm for HMAC
                recv_line,
                self.__cmd_password_hash[1],  # Provide the salt
                100000  # It is recommended to use at least 100,000 iterations of SHA-256
            )
            if passwd == self.__cmd_password_hash[0]:
                logging.info(f"Cmd verification passed from [%s:%d]" % sock.getpeername())
                self.unauth_cmd_conn.pop(sock)
                self.verf_cmd_conn = sock
                sock.send(f"{os.linesep}proxy@{self.host}: ".encode('utf-8'))
                data.outb += recv_line
            else:
                if self.unauth_cmd_conn[sock] >= self.number_of_tries:
                    sock.sendall(f"Premission denied, too much attempts.{os.linesep}".encode('utf-8'))
                    self.close_client(sock)
                else:
                    message = f"Premission denied, please try again.".encode('utf-8')
                    sock.send(message)
                    sock.send(f"{os.linesep}proxy@{self.host}`s password: ".encode('utf-8'))
                    self.unauth_cmd_conn[sock] += 1

    def reboot_session(self):
        """Method break connection with remote machine let it change some parameters."""
        if self.active_protocol in ['ssh', 'telnet']:
            if self.remote_pc:
                self.close_client(self.remote_pc)
            if self.client:
                self.client.send(b'Please reboot connection.')
                self.close_client(self.client)

    def execute_command(self, comm: str):
        """Method make some command, user want to."""
        repl = ''
        flag = True
        logging.info(f"Cmd user ask for command: {comm}.")

        if comm in ["help", "?", "h"]:

            ports_description = {"ls": ["list", 'show connections/ports ("list ?" to see available options)'],
                                 "k": ["kill ip:port", 'kill client connection ("kill ?" to see addition info)'],
                                 "ch": ["change", 'change some params ("change ?" ) to see available options'],
                                 "wake": ["wake up rm_pc_name",
                                          'wake up pc with given name ("wake up ?") to show list of them'],
                                 "log": ["loges row_number",
                                         'show last {row_number} of proxy logs ("log ?" ) to see available options'],
                                 "ex": ["exit", 'close this connection'],
                                 "?/h": ["help", "show reference"]}
            columns_length = [max(len(i) for i in ports_description.keys()),
                              max(len(i[0]) for i in ports_description.values()),
                              max(len(i[1]) for i in ports_description.values())]

            repl += f"Commands can be shortened. The supported commands are:\n{os.linesep}"

            for comm in ports_description.keys():
                repl += f"{comm:<{columns_length[0]}} - {ports_description[comm][0]:<{columns_length[1]}}  " \
                        f"{ports_description[comm][1]:<{columns_length[2]}}{os.linesep}"

        elif comm.startswith("list") or comm.startswith('ls'):
            if comm.startswith("list"):
                comm = comm.lstrip("list").strip(" ")
            else:
                comm = comm.lstrip("ls").strip(" ")

            list_comm = {("clients", "cl"): [self.conn_clients, self.client],
                         ("remote machines", "rm"): [self.conn_rm_machines, self.remote_pc]}

            if comm in ["?", "h"]:

                option_description = {"cl": ["clients", "Show all active and unactive clients."],
                                      "rm": ["remote machines", "Show all active and unactive remote pcs."],
                                      "pr": ["ports", "Show all ports, used with proxy."]}

                columns_length = [max(len(i) for i in option_description.keys()),
                                  max(len(i[0]) for i in option_description.values()),
                                  max(len(i[1]) for i in option_description.values())]

                repl += f"Options can be shortened. The supported options are:\n{os.linesep}"

                for comm in option_description.keys():
                    repl += f"{comm:<{columns_length[0]}} - {option_description[comm][0]:<{columns_length[1]}}  " \
                            f"{option_description[comm][1]:<{columns_length[2]}}{os.linesep}"

            elif comm in ("ports", "pr"):
                ports_description = {f"{self.redirection_port_n}":
                                         ["Port to connection to what start redirection.", ''],
                                     f"{self.protocol_port_n}": [
                                         "System port, sending message, what protocol is used.",
                                         ''],
                                     f"{self.cmd_port_n}":
                                         ["Proxy cli interface.", 'For administrating purposes only!!!!'],
                                     f"{self.wake_up_port_n}": [
                                         "System port, sending message, whether and rm pc to wake up.",
                                         'Do not connect to it manually!!!!'],
                                     f"{self.rm_pcs_ip_check_port_n}": [
                                         "System port, listening of whether global ip of remote pcs have changed, and"
                                         " if so, what is it now.",
                                         'Do not connect to it manually!!!!']
                                     }
                columns_length = [max(len(i) for i in ports_description.keys()),
                                  max(len(i[0]) for i in ports_description.values()),
                                  max(len(i[1]) for i in ports_description.values())]

                repl += f"The supported ports are:\n{os.linesep}"

                for comm in ports_description.keys():
                    repl += f"{comm:<{columns_length[0]}} - {ports_description[comm][0]:<{columns_length[1]}}  " \
                            f"{ports_description[comm][1]:<{columns_length[2]}}{os.linesep}"

            elif any(comm in list_ for list_ in list_comm.keys()):  # first to commands in
                for key_list in list_comm.keys():
                    if comm in key_list:
                        if list_comm[key_list][1]:
                            active_conn = "{0}:{1}".format(*list_comm[key_list][1].getpeername())
                        else:
                            active_conn = None
                        if list_comm[key_list][0]:
                            unactive_conn = ("{0}:{1}{2}".format(*i, os.linesep) for i in list_comm[key_list][0].keys())
                        else:
                            unactive_conn = ["None", ]

                repl = f"Unactive {comm} are:{os.linesep}\t"
                repl += f"\t".join(unactive_conn) + f"{os.linesep}"
                repl += f"Active one is:{os.linesep}" + f"\t{active_conn}"

            else:
                repl = "To get information about command enter: list ?."

        elif comm.startswith('kill') or comm.startswith('k '):
            if comm.startswith("kill"):
                victim = comm.lstrip("kill").strip(" ")
            else:
                victim = comm.lstrip("k ").strip(" ")

            if victim in ["?", "h"]:
                option_description = {"cl": ["[client | active client]", "Close session with active client."],
                                      "-//-": ["IP:PORT", "Close session with client with given IP:PORT."]}

                columns_length = [max(len(i) for i in option_description.keys()),
                                  max(len(i[0]) for i in option_description.values()),
                                  max(len(i[1]) for i in option_description.values())]

                repl += f"Options can be shortened. The supported options are:\n{os.linesep}"

                for option in option_description.keys():
                    repl += f"{option:<{columns_length[0]}} - {option_description[option][0]:<{columns_length[1]}}  " \
                            f"{option_description[option][1]:<{columns_length[2]}}{os.linesep}"

            elif (set(victim) & {f"{i}" for i in range(10)}) and ({':', '.'} & set(victim) == {':', '.'}):
                conn_addr = list(victim.split(":", maxsplit=1))
                conn_addr[1] = int(conn_addr[1])
                conn_addr = tuple(conn_addr)
                if conn_addr in self.conn_clients.keys():
                    self.close_client(self.conn_clients[conn_addr])
                    repl += f"Socket with adders {victim} have been disconnected."
                elif self.client and (conn_addr == self.client.getpeername()):
                    self.close_client(self.client)
                    repl += f"Socket with adders {victim}(active client) have been disconnected."

            elif victim in ["active client", "client", "cl"]:
                if self.client:
                    self.close_client(self.client)
                    repl += f"Active client have been disconnected."
                else:
                    repl += f"No active clients connected."

            else:
                repl = "To get information about command enter: kill ?."

        elif comm.startswith('change') or comm.startswith('ch '):
            if comm.startswith("change"):
                target = comm.lstrip("change").strip(" ")
            else:
                target = comm.lstrip("ch ").strip(" ")

            if target in ["?", "h"]:
                option_description = {"cl": ["[client | active client | client]",
                                             "Change active client to IP:PORT."],
                                      "rm": ["[active rm | remote machine | active remote machine]",
                                             "Change active remote machine to IP:PORT."],
                                      "pr": ["[active protocol | protocol]",
                                             "Change active protocol to PROTOCOL."]}

                columns_length = [max(len(i) for i in option_description.keys()),
                                  max(len(i[0]) for i in option_description.values()),
                                  max(len(i[1]) for i in option_description.values())]

                repl += f"Syntax:{os.linesep}\t change TARGET to [IP:PORT | PROTOCOL].{os.linesep}" \
                        f"Where TARGETs are:{os.linesep}"
                repl += f"Options can be shortened.\n{os.linesep}"

                for option in option_description.keys():
                    repl += f"{option:<{columns_length[0]}} - {option_description[option][0]:<{columns_length[1]}}  " \
                            f"{option_description[option][1]:<{columns_length[2]}}{os.linesep}"

                repl += f"{os.linesep}PROTOCOLs available:{os.linesep}\t" + \
                        f"{os.linesep}\t".join(self.protocols_available)
                repl += f"\n{os.linesep}Active protocol is {self.active_protocol}."

            elif len(target.split(" to ")) == 2 and \
                    target.split(" to ")[0] in ["active client", "client", "cl"
                                                                           "active rm", "remote machine",
                                                "active remote machine", "rm"] and \
                    (set(target.split(" to ")[1]) & {f"{i}" for i in range(10)}) and (
                    {':', '.'} & set(target.split(" to ")[1]) == {':', '.'}):  # active pc or client change

                to_change, change_addr = target.split(" to ")

                change_by_addr = list(change_addr.split(":", maxsplit=1))
                change_by_addr[1] = int(change_by_addr[1])
                change_by_addr = tuple(change_by_addr)  # ["ip", "port"] -> ("ip", port)

                if change_by_addr in self.conn_clients.keys() and to_change in ["active client", "client", "cl"]:
                    change_by_sock = self.conn_clients[change_by_addr]
                    logging.info("Active client changed from [{2}:{3}] to [{0}:{1}]".format(*change_by_addr,
                                                                                            *self.client.getpeername()))
                    repl += "Active client changed from [{2}:{3}] to [{0}:{1}]".format(*change_by_addr,
                                                                                       *self.client.getpeername())

                    # self.conn_clients.update({self.client.getpeername(): self.client})
                    self.reboot_session()
                    self.client = change_by_sock

                elif change_by_addr in self.conn_rm_machines.keys() and to_change in ["active rm", "remote machine",
                                                                                      "active remote machine", "rm"]:
                    change_by_sock = self.conn_rm_machines[change_by_addr]
                    logging.info("Active remote machine changed from [{2}:{3}] to [{0}:{1}]".format(*change_by_addr,
                                                                                                    *self.remote_pc.getpeername()))
                    repl += "Active remote machine changed from [{2}:{3}] to [{0}:{1}]".format(*change_by_addr,
                                                                                               *self.remote_pc.getpeername())
                    # Have not tried
                    self.reboot_session()
                    self.remote_pc = change_by_sock

                else:
                    repl += "Address error. To get information about command enter: change ?."

            elif any(target.startswith(comm) for comm in ["active protocol ", "protocol ", "pr "]) \
                    and len(target.split(" to ")) == 2:  # active protocol change
                protocol = target.split(" to ")[1]

                if protocol == self.active_protocol:
                    repl += "Asked protocol is already implemented."
                elif protocol in self.protocols_available:
                    repl += f"Protocoll changed from {self.active_protocol} to {protocol}."
                    self.active_protocol = protocol
                    self.reboot_session()
                else:
                    repl = "Wrong protocol. To get information about command enter: change ?."

            else:
                repl = "To get information about command enter: change ?."

        elif comm.startswith('wake up') or comm.startswith('wake'):
            if comm.startswith("wake up"):
                target = comm.lstrip("wake up").strip(" ")
            else:
                target = comm.lstrip("wake").strip(" ")
            if target in ["?", "h"]:
                option_description = {"": ["pc_name", "Set signal to wake up pc with given pc_name."]}

                columns_length = [max(len(i) for i in option_description.keys()),
                                  max(len(i[0]) for i in option_description.values()),
                                  max(len(i[1]) for i in option_description.values())]

                repl += f"Syntax:{os.linesep}\t wake TARGET {os.linesep}" \
                        f"Where TARGET is:{os.linesep}"

                for option in option_description.keys():
                    repl += f"{option:<{columns_length[0]}} - {option_description[option][0]:<{columns_length[1]}}  " \
                            f"{option_description[option][1]:<{columns_length[2]}}{os.linesep}"

                repl += f"{os.linesep}PC_NAMEs available:{os.linesep}\t" + \
                        f"{os.linesep}\t".join(["my pc"])

            elif target == "my pc":
                self.need_to_wake_up = "my pc"
                repl += "A wake-up flag is set."

            else:
                repl = "Wrong syntax. To get information about command enter: wake ?."

        elif comm.startswith('loges') or comm.startswith('log '):
            def read_logs(rows_num=-1):
                with open('proxy.log', 'r') as f:
                    all_logs = f.readlines()
                    if rows_num == -1:
                        asked_logs = all_logs
                    else:
                        asked_logs = all_logs[len(all_logs) - rows_num:]

                return f"{os.linesep}".join(asked_logs)

            if comm.startswith("loges"):
                row_num = comm.lstrip("loges").strip(" ")
            else:
                row_num = comm.lstrip("log ").strip(" ")

            if row_num in ["?", "h"]:
                option_description = {"row_num": ["", "Show last {row_num:int} rows of program logs."],
                                      "all": ["", "Show all program logs."]}

                columns_length = [max(len(i) for i in option_description.keys()),
                                  max(len(i[0]) for i in option_description.values()),
                                  max(len(i[1]) for i in option_description.values())]

                repl += f"Syntax:{os.linesep}\t log TARGET {os.linesep}" \
                        f"Where TARGET is:{os.linesep}"

                for option in option_description.keys():
                    repl += f"{option:<{columns_length[0]}} {option_description[option][0]:<{columns_length[1]}}  " \
                            f"{option_description[option][1]:<{columns_length[2]}}{os.linesep}"

            elif row_num == 'all':
                repl += read_logs()

            elif row_num.isdigit():
                row_num = int(row_num)
                repl += read_logs(row_num)

            else:
                repl = "Wrong syntax. To get information about command enter: log ?."

        elif comm.startswith("exit") or comm.startswith('ex '):
            if comm.startswith("exit"):
                comm = comm.lstrip("exit").strip(" ")
            else:
                comm = comm.lstrip("ex ").strip(" ")

            if not comm:
                self.close_client(self.verf_cmd_conn)
            else:
                repl = "Wrong syntax. To get information about command enter: help."


        else:
            flag = False
        return flag, repl

    def command_from_verif_user(self, key, mask):
        """Method run user on cmd socket command."""
        sock = key.fileobj
        recv_line = self.read_from_buffer(sock)
        if recv_line:
            comm = recv_line.decode('utf-8')
            if comm:
                flag, repl = self.execute_command(comm)
                if self.verf_cmd_conn:
                    if flag:
                        sock.sendall(bytes(repl, encoding='utf-8'))
                        sock.send(f"{os.linesep}proxy@{self.host}: ".encode('utf-8'))
                    else:
                        sock.send('Unacceptable command. Enter "?" or "help" for more information'.encode('utf-8'))
                        sock.send(f"{os.linesep}proxy@{self.host}: ".encode('utf-8'))

    def run(self):
        """Method handle and support server live."""
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    self.add_client(key.fileobj)
                else:
                    if self.remote_pc and self.client and (key.fileobj in (self.remote_pc, self.client)):
                        self.redirect_inf(key, mask)
                    if key.fileobj == self.verf_cmd_conn:
                        self.read_to_buffer(key.fileobj, mask)
                        self.command_from_verif_user(key, mask)
                    elif key.fileobj in self.unauth_cmd_conn:
                        self.read_to_buffer(key.fileobj, mask)
                        self.auth_cmd_conn(key, mask)


def main():
    """Main project body. Function, although, return appropriate message
     if something goes wrong."""
    while True:
        try:
            Redirection(host_ip='0.0.0.0', redirection_port=1, cmd_port=1,
                        wake_up_port=1, active_protocol_port=1, rm_pcs_ip_check_port=1,
                        settings_from_file=True).run()
        except (ConnectionResetError, OSError) as err:
            logging.error(err)


if __name__ == '__main__':
    main()
