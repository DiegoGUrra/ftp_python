"""
FTP Conn for python
Author: Diego G.
Date: 2025-09-01
"""

import argparse
import json
from os import path, listdir
import readline
import socket
import sys
from getpass import getpass
import threading

CONTROL_PORT = 5000
DATA_PORT = 5050
TARGET = "TARGET IP"
HOST = "0.0.0.0"
BUFFER_SIZE = 1024
LOGIN_TRIES = 3
commands = ["AYUDA", "LISTAR", "DESCARGAR", "SUBIR", "SALIR", "CD"]
users = {"diego": "pass", "anon": "pass"}
FTP_ROOT = path.curdir
FTP_MESSAGES = {
    "HELLO": {"code": 220, "message": "Bienvenido al servidor FTP"},
    "USER_OK": {"code": 331, "message": "Usuario correcto, ingrese la clave"},
    "LOGIN_SUCCESS": {"code": 230, "message": "Login exitoso"},
    "LOGIN_FAIL": {"code": 530, "message": "Usuario o clave incorrectos"},
    "MAX_ATTEMPTS": {"code": 421, "message": "Demasiados intentos, cerrando conexión"},
    "COMMAND_OK": {"code": 200, "message": "Comando ejecutado correctamente"},
    "DIR_CHANGED": {"code": 250, "message": "Directorio cambiado correctamente"},
    "COMMAND_UNKNOWN": {"code": 500, "message": "Comando no reconocido"},
    "DISCONNECT": {"code": 221, "message": "Cerrando conexión"},
    "FILE_NOT_FOUND": {"code": 550, "message": "Archivo no encontrado"},
    "DIR_NOT_FOUND": {"code": 550, "message": "Directorio no encontrado"},
    "ACCESS_DENIED": {"code": 550, "message": "Acceso denegado"},
    "NOT_DIR": {"code": 550, "message": "No es directorio"},
    "READY_FOR_DATA": {"code": 150, "message": "Preparado para recibir datos"},
    "TRANSFER_COMPLETE": {"code": 226, "message": "Transferencia completada"},
}
bcolors = {
    "HEADER": "\033[95m",
    "OKBLUE": "\033[94m",
    "OKCYAN": "\033[96m",
    "OKGREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m",
}


class FTPServer:
    def __init__(self, host, conn_port, data_port, root_dir):
        self.host = host
        self.conn_port = conn_port
        self.data_port = data_port
        self.running = False
        self.server_socket = None
        self.root_dir = path.abspath(root_dir)
        self.clients = {}
        self.lock = threading.Lock()

    def start(self):
        self.running = True
        print(f"Iniciando Servidor en {self.host}: {self.conn_port}")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.conn_port))
        # TODO: Use select before the socket.accept()
        self.server_socket.listen()
        self.server_socket.settimeout(5)
        try:
            threading.Thread(target=self.console, daemon=True).start()
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except OSError as e:  # Bad file descriptor
                    if self.running:
                        print(f"Error: {e}")
                    break
                # with self.lock:
                    # self.clients[addr] = conn
                print(f"Se conectó {addr}, en path: {self.root_dir}")
                threading.Thread(
                    target=self.handle_client, args=(conn, addr), daemon=True
                ).start()
        except KeyboardInterrupt:
            print("Servidor ha sido detenido manualmente")
        finally:
            self.shutdown()

    def shutdown(self):
        if not self.running:
            print("Ya se está cerrando")
            return
        print("Cerrando Servidor...")
        self.running = False
        with self.lock:
            for _, conn in self.clients.items():
                try:
                    conn.close()
                except:
                    pass
        self.clients.clear()
        try:
            if self.server_socket is not None:
                self.server_socket.close()
            print("Se cerró")
        except OSError:
            print("OS error")

    def handle_client(self, conn, addr):
        uuid = self.handle_new_conn( addr, conn)
        username = self.handle_login(conn)
        curr_dir = self.root_dir
        if username:
            self.login_client(uuid, username)
        while True:
            data = self.recv_message(conn)
            client = self.clients.get(uuid)
            if not client or not client.get("logged", False):
                break
            ip, _ = addr
            if not data:
                break
            cmd = data.get("cmd")
            params = data.get("params")
            size = data.get("size")
            if cmd.upper() == "SALIR":
                break
            elif cmd.upper() == "LISTAR":
                self.handle_ls(conn, ip, curr_dir)
            elif cmd.upper() == "DESCARGAR":
                self.handle_download(conn, params[0], curr_dir, ip)
            elif cmd.upper() == "SUBIR":
                self.handle_upload(conn, params[0], size, curr_dir, ip)
            elif cmd.upper() == "CD":
                curr_dir = self.handle_cd(conn, params[0], curr_dir)
            else:
                conn.send(json.dumps(FTP_MESSAGES["COMMAND_UNKNOWN"]).encode())
        self.handle_quit(conn)
        self.disconnect_client(uuid)

    def console(self):
        while self.running:
            cmd = input("ftp> ")
            if cmd.upper() == "LIST":
                with self.lock:
                    for client_id, client_info in self.clients.items():
                        print(f"ID: {client_id}, Addr: {client_info['addr']}, User: {client_info['user']}")
            elif cmd.startswith("kick "):
                client_id = cmd.split(" ")[1]
                with self.lock:
                    client = self.clients.pop(int( client_id ), None)
                    print(f"Expulsado el cliente {client}")
            elif cmd == "exit":
                self.shutdown()
                break
            else:
                print("Comandos: list, kick <id> y exit")
        print("Terminó consola")

    def handle_new_conn(self, addr, conn):
        """
        Creates a clients, with a unique id
        """
        session_id = len( self.clients )
        with self.lock:
            self.clients[session_id] = {
                "addr": addr,
                "user": None,
                "logged": False,
                "conn": conn
            }
        return session_id

    def login_client(self, session_id, username):
        """
        Adds username and logged into a client
        """
        with self.lock:
            self.clients[session_id]["user"] = username
            self.clients[session_id]["logged"] = True

    def disconnect_client(self, session_id):
        """
        Disconnects a client
        """
        with self.lock:
            # print("DISCONNECT SELF:", id(self))
            # print("DISCONNECT CLIENTS:", id(self.clients))
            client = self.clients.pop(session_id, None)
            if client:
                print(f"Cliente {session_id} se ha desconectado")

    def handle_login(self, conn):
        """
        Handles login
        """
        tries = 0
        self.send_message(conn, "HELLO")
        while tries < LOGIN_TRIES:
            username = conn.recv(BUFFER_SIZE).decode().strip()
            if username in users:
                self.send_message(conn, "USER_OK")
                password = conn.recv(BUFFER_SIZE).decode().strip()
                if (username, password) in users.items():
                    self.send_message(conn, "LOGIN_SUCCESS")
                    return username
            self.send_message(conn, "LOGIN_FAIL")
            tries += 1
        conn.send(json.dumps(FTP_MESSAGES["MAX_ATTEMPTS"]).encode())
        self.send_message(conn, "MAX_ATTEMTPS")
        return None

    def handle_ls(self, conn, ip, curr_path="."):
        """
        List files in a dir
        """
        try:
            items = []
            for item in listdir(curr_path):
                full_path = path.join(curr_path, item)
                e = {"name": item, "isDir": path.isdir(full_path)}
                items.append(e)
            parsed_items = {i: key for i, key in enumerate(items)}
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_socket.bind((self.host, DATA_PORT))
                data_socket.listen(1)
                data_socket.settimeout(10)
                print(f"Escuchando en {DATA_PORT}")
                msg = self.send_message(conn, "READY_FOR_DATA", **{"port": DATA_PORT})
                print(f"Sent message: {msg}")
                data_conn, addr = data_socket.accept()
                if ip != addr[0]:
                    return
                with data_conn:
                    print(f"IP: {addr}, PORT: {DATA_PORT}")
                    data_conn.sendall(json.dumps(parsed_items).encode())
                    data_conn.close()
                data_socket.close()
            self.send_message(conn, "TRANSFER_COMPLETE")
        except FileNotFoundError:
            self.send_message(conn, "FILE_NOT_FOUND")
        except ConnectionResetError as e:
            print(f"Ocurrió un error: {e}")
        except Exception as e:
            print(f"Error: {e}")

    def handle_download(self, conn, filename, curr_dir, ip):
        """
        Downloads a file
        """
        full_path = path.join(curr_dir, filename)
        if not path.isfile(full_path):
            self.send_message(conn, "FILE_NOT_FOUND")
            return
        try:
            size = path.getsize(full_path)
            self.send_message(
                conn, "READY_FOR_DATA", **{"size": size, "port": self.data_port}
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_socket.bind((self.host, self.data_port))
                data_socket.listen(1)
                data_socket.settimeout(10)
                print(f"Escuchando en {self.data_port}")
                # conn.sendall(f"PORT {DATA_PORT}\r\n".encode())
                data_conn, addr = data_socket.accept()
                # check if break is a correct out statement, prob need something more thoughtful to exit or retry the conn
                if ip != addr[0]:
                    return
                with data_conn, open(full_path, "rb") as f:
                    while chunk := f.read(BUFFER_SIZE):
                        data_conn.sendall(chunk)
            self.send_message(conn, "TRANSFER_COMPLETE")
        except FileNotFoundError:
            self.send_message(conn, "FILE_NOT_FOUND")
        except ConnectionResetError as e:
            print(f"Ocurrió un error: {e}")
        except Exception as e:
            print(f"Error: {e}")

    def handle_upload(self, conn, filename, size, curr_dir, ip):
        """
        Handles upload
        """
        self.send_message(conn, "READY_FOR_DATA", **{"size": size, "port": DATA_PORT})
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
            data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            data_socket.bind((self.host, DATA_PORT))
            data_socket.listen(1)
            data_socket.settimeout(10)
            data_conn, addr = data_socket.accept()
            if ip != addr[0]:
                return
            full_path = path.join(curr_dir, filename)
            with data_conn, open(full_path, "wb") as f:
                received = 0
                while received < size:
                    chunk = data_conn.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
        self.send_message(conn, "TRANSFER_COMPLETE")

    def handle_quit(self, conn):
        """
        Exits
        """
        self.send_message(conn, "DISCONNECT")
        conn.close()

    def handle_cd(self, conn, dir, curr_dir):
        """
        Changes Dir Server side
        """
        next_dir = path.abspath(path.join(curr_dir, dir))
        if not path.exists(next_dir):
            self.send_message(conn, "NOT_DIR")
        elif path.commonpath([self.root_dir, next_dir]) != self.root_dir:
            self.send_message(conn, "ACCESS_DENIED")
        elif path.isdir(next_dir):
            self.send_message(conn, "DIR_CHANGED")
            return next_dir
        else:
            self.send_message(conn, "DIR_NOT_FOUND")
        return curr_dir

    def send_message(self, conn, key, **kwargs):
        """
        Encodes and sends a JSON message to the client, it also can send data
        """
        msg = FTP_MESSAGES.get(key)
        if not msg:
            return None
        msg = {**msg, **kwargs}
        conn.sendall(json.dumps(msg).encode())
        return msg

    def recv_message(self, conn):
        """
        Decodes message
        """
        data = conn.recv(BUFFER_SIZE)
        if not data:
            return None
        return json.loads(data.decode())

class Client():
    def __init__(self,target, control_port ):
        self.target = target
        self.control_port = control_port
        self.start()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.target, self.control_port))
                conn_status = True
                # LOGIN BLOCK
                conn_status = self.login(s)
                self.init_autocomplete()
                while conn_status:
                    # COMMAND BLOCK
                    full_cmd = input("ftp> ").strip()
                    if not full_cmd:
                        continue
                    full_cmd = self.send_message(s, full_cmd)
                    if full_cmd is None:
                        continue
                    cmd = full_cmd.get("cmd", "")
                    params = full_cmd.get("params", "")
                    message = self.recv_message(s)
                    port = message.get("port")
                    if message["code"] == 221:
                        # salir
                        conn_status = False
                    elif message["code"] == 500:
                        ...
                    elif message["code"] == 150:
                        if cmd.upper() == "LISTAR":
                            self.ls(s, port)
                        elif cmd.upper() == "DESCARGAR":
                            self.download(s, message["size"], params[0], port)
                        elif cmd.upper() == "SUBIR":
                            self.upload(s, params[0], port)
                self.quit(s)
            except KeyboardInterrupt as e:
                print(f"Cerrando conexion: {e}")
            except Exception as e:
                print(f"Error inesperado: {e}")
            finally:
                self.quit(s)

    def login(self, socket):
        """
        Client login
        """
        try:
            message = self.recv_message(socket)
            while message["code"] != 421:
                user = input("USUARIO: ")
                if not user:
                    continue
                socket.sendall(user.encode())
                message = self.recv_message(socket)
                if message["code"] == 331:
                    pwd = getpass(prompt="PASS: ")
                    socket.sendall(pwd.encode())
                    message = self.recv_message(socket)
                    if message["code"] == 230:
                        return True
        except json.JSONDecodeError:
            return False
        return False

    def send_message(self, s, full_cmd):
        """
        Encodes and sends a JSON message to the server and
        returns the created dict
        """
        cmd, *params = full_cmd.split()
        msg = {"cmd": cmd}
        #FIX: el return None xq se cae
        if cmd.upper() == "SUBIR":
            if len(params) == 0 or  not path.isfile(params[0]):
                print("Archivo invalido o no encontrado")
                return None
            msg.update({"size": path.getsize(params[0])})
        if params:
            msg.update({"params": params})
        s.sendall(json.dumps(msg).encode())
        return msg

    def ls(self, s, port):
        """
        Show listed files and dirs
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
            data_socket.connect((self.target, port))
            data_bytes = b""
            while True:
                chunk = data_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data_bytes += chunk
            data = json.loads(data_bytes.decode())
        message = self.recv_message(s)
        print("\n")
        if message["code"] == 226:
            for e in data.values():
                if e["isDir"]:
                    print(f"{bcolors['OKBLUE']}{e['name']}{bcolors['ENDC']}")
                else:
                    print(f"{e['name']}")


    def upload(self, s, filename, port):
        """
        Uploads a file
        """
        if not path.isfile(filename):
            print(f"Archivo {filename} no encontrado")
            return
        print(f"Intentando conexión en {self.target} - {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket, open(
            filename, "rb"
        ) as f:
            data_socket.connect((self.target, port))
            with data_socket, open(filename, "rb") as f:
                while chunk := f.read(BUFFER_SIZE):
                    data_socket.sendall(chunk)
        message = self.recv_message(s)
        if message["code"] == 226:
            print("\nArchivo Subido\n")


    def download(self, s, size, filename, port):
        """
        Downloads a file
        """
        # port = int(s.recv(BUFFER_SIZE).decode().split(" ")[2])
        print(f"Intentando conexión en {self.target} - {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket, open(
            filename, "wb"
        ) as f:
            data_socket.connect((self.target, port))
            received = 0
            while received < size:
                chunk = data_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
        message = self.recv_message(s)
        if message["code"] == 226:
            print("\nArchivo Descargado\n")

    def quit(self, s):
        """
        Exits client side
        """
        s.close()
        sys.exit(0)

    def cd(self, s):
        """
        Changes Dir Client side
        """
        self.recv_message(s)


    def recv_message(self, s):
        """
        Receives a json messages decodes it and print it formated code - message
        """
        data = s.recv(BUFFER_SIZE)
        message = json.loads(data.decode())
        color = bcolors['FAIL'] if message['code']>=500 or message['code'] == 421  else bcolors['OKGREEN']
        print(f"{color}{message['code']} - {message['message']}{bcolors['ENDC']}")
        return message

    def init_autocomplete(self):
        """
        Init autocomplete
        """
        def completer(text, state):
            """
            Completes text when using tab
            """
            options = [x for x in commands if x.startswith(text.upper())]
            if state < len(options):
                return options[state]
            return None
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
def help():
    """
    Shows available commands
    """


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Servidor FTP",
        description="Servidor de ftp por socket",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server_parser = subparsers.add_parser("server", help="Corre el programa en modo servidor")
    server_parser.add_argument("-H", "--host", default=HOST, help="IP de Host")
    server_parser.add_argument("-C", "--control_port", type=int, default=CONTROL_PORT, help="Puerto de control")
    server_parser.add_argument("-D", "--data_port", type=int, default=DATA_PORT, help="Puerto de data")
    server_parser.add_argument("-R", "--root_dir", default=FTP_ROOT, help="raiz de directorio")

    client_parser = subparsers.add_parser("client", help="Corre el programa en modo cliente")
    client_parser.add_argument("target_ip", help="IP del servidor al cual conectarse")
    client_parser.add_argument("-p", "--port", default=CONTROL_PORT, type=int,help="Puerto de control")

    args = parser.parse_args()

    if args.mode == "server":
        ftp_server = FTPServer(args.host, args.control_port, args.data_port, args.root_dir)
        ftp_server.start()
    else:
        client = Client(args.target_ip, args.port)
