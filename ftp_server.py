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
import uuid

CONTROL_PORT = 5000
DATA_PORT = 5050
TARGET = "TARGET IP"
HOST = "0.0.0.0"
BUFFER_SIZE = 1024
LOGIN_TRIES = 3
commands = ["AYUDA", "LISTAR", "DESCARGAR", "SUBIR", "SALIR", "CD"]
users = {"diego": "pass", "anon": "pass"}
FTP_ROOT = "."
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
        self.root_dir = root_dir
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
        print(f"is running console? {self.running}")
        with self.lock:
            for conn in self.clients.values():
                conn.close()
        self.clients.clear()
        try:
            if self.server_socket is not None:
                self.server_socket.close()
            print("Se cerró")
        except OSError:
            print("OS error")

    def handle_client(self, conn, addr):
        uuid = self.handle_new_conn( addr)
        connected, username = self.handle_login(conn)
        curr_dir = self.root_dir
        if connected:
            self.login_client(uuid, username)
        while connected:
            data = self.recv_message(conn)
            ip, _ = addr
            if not data:
                print(f"received: {data}")
                break
            cmd = data.get("cmd")
            params = data.get("params")
            size = data.get("size")
            print("Received: ", data)
            if cmd.upper() == "SALIR":
                connected = False
            elif cmd.upper() == "LISTAR":
                self.handle_ls(conn, ip, curr_dir)
            elif cmd.upper() == "DESCARGAR":
                self.handle_download(conn, params[0], curr_dir, ip)
            elif cmd.upper() == "SUBIR":
                self.handle_upload(conn, params[0], size, curr_dir, ip)
            elif cmd.upper() == "CD":
                curr_dir = self.handle_cd(conn, params[0], curr_dir)
                print(f"current dir: {curr_dir}")
            else:
                conn.send(json.dumps(FTP_MESSAGES["COMMAND_UNKNOWN"]).encode())
        self.handle_quit(conn)
        self.disconnect_client(uuid)

    def console(self):
        while self.running:
            cmd = input("ftp> ")
            if cmd.upper() == "LIST":
                with self.lock:
                    # print("DISCONNECT SELF:", id(self))
                    # print("DISCONNECT CLIENTS:", id(self.clients))
                    for client_id, client_info in self.clients.items():
                        print(f"ID: {client_id}, Addr: {client_info['addr']}, User: {client_info['user']}")
            elif cmd.startswith("kick "):
                client_id = cmd.split(" ")[1]
                with self.lock:
                    print(self.clients)
                    client = self.clients.pop(int( client_id ), None)
                    print(f"Expulsado el cliente {client}")
                    # for addr, conn in list(self.clients.items()):
                    #     if client_ip in str(addr):
                    #         self.handle_quit(conn)
                    #         self.clients.pop(addr, None)
                    #         print(f"Expulsado el cliente {addr}")
                    #         break
            elif cmd == "exit":
                self.shutdown()
                break
            else:
                print("Comandos: list, kick <id> y exit")
        print("Terminó consola")

    def handle_new_conn(self, addr):
        """
        Creates a clients, with a unique id
        """
        session_id = len( self.clients )
        with self.lock:
            self.clients[session_id] = {
                "addr": addr,
                "user": None,
                "logged": False,
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
            print({"clients": self.clients})
            client = self.clients.pop(session_id, None)
            print({ "client":client })
            if client:
                print(f"Sesión {session_id} se ha desconectado")
            print({"clients": self.clients})

    def handle_login(self, conn):
        """
        Handles login
        """
        tries = 0
        while tries < LOGIN_TRIES:
            self.send_message(conn, "HELLO")
            username = conn.recv(BUFFER_SIZE).decode().strip()
            print(username)
            if username in users:
                self.send_message(conn, "USER_OK")
                password = conn.recv(BUFFER_SIZE).decode().strip()
                if (username, password) in users.items():
                    self.send_message(conn, "LOGIN_SUCCESS")
                    return True, username
            self.send_message(conn, "LOGIN_FAIL")
            tries += 1
        conn.send(json.dumps(FTP_MESSAGES["MAX_ATTEMPTS"]).encode())
        self.send_message(conn, "MAX_ATTEMTPS")
        return False, None

    def handle_ls(self, conn, ip, curr_path="."):
        """
        List files in a dir
        """
        # TODO: implement ip check
        try:
            items = []
            for item in listdir(curr_path):
                full_path = path.join(curr_path, item)
                e = {"name": item, "isDir": path.isdir(full_path)}
                items.append(e)
            parsed_items = {i: key for i, key in enumerate(items)}
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                print(f"{data_socket}")
                data_socket.bind((HOST, DATA_PORT))
                data_socket.listen(1)
                data_socket.settimeout(10)
                print(f"Escuchando en {DATA_PORT}")
                msg = self.send_message(conn, "READY_FOR_DATA", **{"port": DATA_PORT})
                print(f"Sent message: {msg}")
                data_conn, addr = data_socket.accept()
                if ip != addr[0]:
                    return
                print(f"cliente {addr}")
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
            print(
                {
                    "ADDRESS": ip,
                    "CURR_ADDR": curr_dir,
                    "FILENAME": filename,
                    "FULL_PATH": full_path,
                }
            )
            size = path.getsize(full_path)
            self.send_message(
                conn, "READY_FOR_DATA", **{"size": size, "port": DATA_PORT}
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                print(f"{data_socket}")
                data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_socket.bind((HOST, DATA_PORT))
                data_socket.listen(1)
                data_socket.settimeout(10)
                print(f"Escuchando en {DATA_PORT}")
                # conn.sendall(f"PORT {DATA_PORT}\r\n".encode())
                data_conn, addr = data_socket.accept()
                # check if break is a correct out statement, prob need something more thoughtful to exit or retry the conn
                print(f"cliente {ip}= {addr}")
                if ip != addr[0]:
                    return
                print(f"cliente {addr}")
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
            print(f"{data_socket}")
            data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            data_socket.bind((HOST, DATA_PORT))
            data_socket.listen(1)
            data_socket.settimeout(10)
            print(f"Escuchando en {DATA_PORT}")
            # conn.sendall(f"PORT {DATA_PORT}\r\n".encode())
            # same as handle_download
            data_conn, addr = data_socket.accept()
            if ip != addr[0]:
                return
            print(f"cliente {ip}= {addr}")
            full_path = path.join(curr_dir, filename)
            with data_conn, open(filename, "wb") as f:
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
        elif path.commonpath([FTP_ROOT, next_dir]) != FTP_ROOT:
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
                    print(conn_status)
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
                    elif message["code"] == 200:
                        print("it worked")
                    # elif message["code"] == 226:
                    elif message["code"] == 150:
                        if cmd.upper() == "LISTAR":
                            self.ls(s, port)
                        elif cmd.upper() == "DESCARGAR":
                            self.download(s, message["size"], params[0], port)
                        elif cmd.upper() == "SUBIR":
                            self.upload(s, params[0], port)
                    # elif message["code"] == 250:
                    # if cmd.upper() == "CD":
                    # cd(s,params[0], port)
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
        print("client login")
        data = socket.recv(BUFFER_SIZE)
        if not data:
            print("No se ha encontrado el servidor")
            return False
        try:
            message = json.loads(data.decode())
            user = input("USUARIO: ")
            socket.sendall(user.encode())
            while message["code"] != 421:
                print("hello world")
                data = socket.recv(BUFFER_SIZE)
                message = json.loads(data.decode())
                if message["code"] == 331:
                    print(f"{message['code']} - {message['message']}")
                    pwd = getpass(prompt="PASS: ")
                    socket.sendall(pwd.encode())
                    data = socket.recv(BUFFER_SIZE)
                    message = json.loads(data.decode())
                    print(f"{message['code']} - {message['message']}")
                    if message["code"] == 230:
                        return True
        except json.JSONDecodeError:
            print(data.decode())
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
        print(f"{port}!!")
        print(f"Intentando conexión en {TARGET} - {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
            data_socket.connect((TARGET, port))
            print("Conectado!")
            data_bytes = b""
            while True:
                chunk = data_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data_bytes += chunk
            data = json.loads(data_bytes.decode())
        message = self.recv_message(s)
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
        print(f"Intentando conexión en {TARGET} - {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket, open(
            filename, "rb"
        ) as f:
            data_socket.connect((TARGET, port))
            # print("Conectado!")
            with data_socket, open(filename, "rb") as f:
                while chunk := f.read(BUFFER_SIZE):
                    data_socket.sendall(chunk)
        message = self.recv_message(s)
        if message["code"] == 226:
            print("Hola")


    def download(self, s, size, filename, port):
        """
        Downloads a file
        """
        # port = int(s.recv(BUFFER_SIZE).decode().split(" ")[2])
        print(f"Intentando conexión en {TARGET} - {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket, open(
            filename, "wb"
        ) as f:
            data_socket.connect((TARGET, port))
            print("Conectado!")
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

    def cd(self, s, dir, port):
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
        print(f"{message['code']} - {message['message']}")
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
        prog="SOCKET CONNECTION",
        description="This program connects thru sockets",
    )
    parser.add_argument("target_ip", help="target IP for conn")
    parser.add_argument("-H", "--host", help="host IP for conn")
    parser.add_argument("-p", "--port", help="Port for conn")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["server", "client"],
        required=True,
        help="run in client or server mode",
    )
    args = parser.parse_args()
    TARGET = args.target_ip
    HOST = args.host is not None if args.host else HOST
    CONTROL_PORT = args.port is not None if args.port else CONTROL_PORT
    FTP_ROOT = path.abspath(path.curdir)
    print(args.target_ip, args.host, args.port)
    print(TARGET, HOST, CONTROL_PORT)
    if args.mode == "server":
        ftp_server = FTPServer(HOST, CONTROL_PORT, DATA_PORT, FTP_ROOT)
        ftp_server.start()
    else:
        client = Client(TARGET, CONTROL_PORT)
