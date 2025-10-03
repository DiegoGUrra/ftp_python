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

# import threading
CONTROL_PORT = 5000
DATA_PORT = 5050
TARGET = "TARGET IP"
HOST = "0.0.0.0"
BUFFER_SIZE = 1024
LOGIN_TRIES = 3
commands = ["AYUDA", "LISTAR", "DESCARGAR", "SUBIR", "SALIR","CD"]
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


def server():
    """
    Opens a socket server
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, CONTROL_PORT))
        s.listen()
        try:
            conn, addr = s.accept()
            ip, port = addr
            curr_dir = "."
            with conn:
                print(f"Connected by {addr}, root path: {FTP_ROOT}")
                # connected = True
                connected = handle_login(conn)
                while connected:
                    data = recv_sv_message(conn)
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
                        handle_ls(conn,curr_dir)
                    elif cmd.upper() == "DESCARGAR":
                        handle_download(conn, params[0],curr_dir, ip)
                    elif cmd.upper() == "SUBIR":
                        handle_upload(conn, params[0], size,curr_dir, ip)
                    elif cmd.upper() == "CD":
                        curr_dir = handle_cd(conn, params[0],curr_dir)
                        print(f"current dir: {curr_dir}")
                    else:
                        conn.send(json.dumps(FTP_MESSAGES["COMMAND_UNKNOWN"]).encode())
                handle_quit(conn)
        except ConnectionResetError as e:
            print(f"Ocurrió un error: {e}")
        except KeyboardInterrupt as e:
            print(f"Cerrado por usuario: {e}")
        finally:
            print("Cerrando conexión y servidor")
            try:
                conn.close()
            finally:
                s.close()


def client():
    """
    Opens a client socket
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((TARGET, CONTROL_PORT))
            conn_status = True
            # LOGIN BLOCK
            conn_status = login(s)
            init_autocomplete()
            while conn_status:
                print(conn_status)
                # COMMAND BLOCK
                full_cmd = input("ftp> ").strip()
                if not full_cmd:
                    continue
                full_cmd = send_client_message(s, full_cmd)
                cmd = full_cmd.get("cmd")
                params = full_cmd.get("params")
                message = recv_message(s)
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
                        ls(s, port)
                    elif cmd.upper() == "DESCARGAR":
                        download(s, message["size"], params[0], port)
                    elif cmd.upper() == "SUBIR":
                        upload(s, params[0], port)
                #elif message["code"] == 250:
                    #if cmd.upper() == "CD":
                        #cd(s,params[0], port)
            client_quit(s)
        except KeyboardInterrupt as e:
            print(f"Cerrando conexion: {e}")
        except Exception as e:
            print(f"Error inesperado: {e}")
        finally:
            client_quit(s)


def ls(s, port):
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
    message = recv_message(s)
    if message["code"] == 226:
        for e in data.values():
            if e["isDir"]:
                print(f"{bcolors['OKBLUE']}{e['name']}{bcolors['ENDC']}")
            else:
                print(f"{e['name']}")


def handle_ls(conn, curr_path="."):
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
        # print(parsed_items)
        # send message if the data fetch is correct
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
            data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print(f"{data_socket}")
            data_socket.bind((HOST, DATA_PORT))
            data_socket.listen(1)
            data_socket.settimeout(10)
            print(f"Escuchando en {DATA_PORT}")
            msg = send_message(conn, "READY_FOR_DATA", **{"port": DATA_PORT})
            print(f"Sent message: {msg}")
            # conn.sendall(f"PORT {DATA_PORT}\r\n".encode())
            data_conn, ip = data_socket.accept()
            print(f"cliente {ip}")
            with data_conn:
                print(f"IP: {ip}, PORT: {DATA_PORT}")
                data_conn.sendall(json.dumps(parsed_items).encode())
                data_conn.close()
            data_socket.close()
        send_message(conn, "TRANSFER_COMPLETE")
    except FileNotFoundError:
        conn.send(json.dumps(FTP_MESSAGES["FILE_NOT_FOUND"]).encode())
    except ConnectionResetError as e:
        print(f"Ocurrió un error: {e}")
    except Exception as e:
        print(f"Error: {e}")


def handle_login(conn):
    """
    Handles login
    """
    tries = 0
    while tries < LOGIN_TRIES:
        conn.send(json.dumps(FTP_MESSAGES["HELLO"]).encode())
        username = conn.recv(BUFFER_SIZE).decode().strip()
        print(username)
        if username in users:
            conn.send(json.dumps(FTP_MESSAGES["USER_OK"]).encode())
            password = conn.recv(BUFFER_SIZE).decode().strip()
            if (username, password) in users.items():
                conn.send(json.dumps(FTP_MESSAGES["LOGIN_SUCCESS"]).encode())
                return True
        conn.send(json.dumps(FTP_MESSAGES["LOGIN_FAIL"]).encode())
        tries += 1
    conn.send(json.dumps(FTP_MESSAGES["MAX_ATTEMPTS"]).encode())
    return False


def login(s):
    """
    Client login
    """
    print("client login")
    data = s.recv(BUFFER_SIZE)
    if not data:
        print("No se ha encontrado el servidor")
        return False
    try:
        message = json.loads(data.decode())
        user = input("USUARIO: ")
        s.sendall(user.encode())
        while message["code"] != 421:
            print("hello world")
            data = s.recv(BUFFER_SIZE)
            message = json.loads(data.decode())
            if message["code"] == 331:
                print(f"{message['code']} - {message['message']}")
                pwd = getpass(prompt="PASS: ")
                s.sendall(pwd.encode())
                data = s.recv(BUFFER_SIZE)
                message = json.loads(data.decode())
                print(f"{message['code']} - {message['message']}")
                if message["code"] == 230:
                    return True
    except json.JSONDecodeError:
        print(data.decode())
        return False
    return False


def upload(s, filename, port):
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
    message = recv_message(s)
    if message["code"] == 226:
        print("Hola")


def handle_upload(conn, filename, size, curr_dir, ip):
    """
    Handles upload
    """
    send_message(conn, "READY_FOR_DATA", **{"size": size, "port": DATA_PORT})
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
        if ip != addr:
            return
        print(f"cliente {ip}= {addr}")
        full_path = path.join(curr_dir,filename)
        with data_conn, open(filename, "wb") as f:
            received = 0
            while received < size:
                chunk = data_conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
    send_message(conn, "TRANSFER_COMPLETE")

def download(s, size, filename, port):
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
    message = recv_message(s)
    if message["code"] == 226:
        print("\nArchivo Descargado\n")


def handle_download(conn, filename, curr_dir, ip):
    """
    Downloads a file
    """
    full_path = path.join(curr_dir, filename)
    if not path.isfile(full_path):
        send_message(conn, "FILE_NOT_FOUND")
        return
    try:
        print({"ADDRESS":ip, "CURR_ADDR": curr_dir, "FILENAME":filename, "FULL_PATH": full_path})
        size = path.getsize(full_path)
        send_message(conn, "READY_FOR_DATA", **{"size": size, "port": DATA_PORT})
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
            print(f"{data_socket}")
            data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            data_socket.bind((HOST, DATA_PORT))
            data_socket.listen(1)
            data_socket.settimeout(10)
            print(f"Escuchando en {DATA_PORT}")
            # conn.sendall(f"PORT {DATA_PORT}\r\n".encode())
            data_conn, addr = data_socket.accept()
            #check if break is a correct out statement, prob need something more thoughtful to exit or retry the conn
            print(f"cliente {ip}= {addr}")
            if ip != addr[0]: 
                return
            print(f"cliente {addr}")
            with data_conn, open(full_path, "rb") as f:
                while chunk := f.read(BUFFER_SIZE):
                    data_conn.sendall(chunk)
        send_message(conn, "TRANSFER_COMPLETE")
    except FileNotFoundError:
        conn.send(json.dumps(FTP_MESSAGES["FILE_NOT_FOUND"]).encode())
    except ConnectionResetError as e:
        print(f"Ocurrió un error: {e}")
    except Exception as e:
        print(f"Error: {e}")


def handle_quit(conn):
    """
    Exits
    """
    conn.send(json.dumps(FTP_MESSAGES["DISCONNECT"]).encode())
    conn.close()


def client_quit(s):
    """
    Exits client side
    """
    s.close()
    sys.exit(0)

def handle_cd(conn, dir,curr_dir):
    """
    Changes Dir Server side
    """ 
    next_dir = path.abspath(path.join(curr_dir,dir))
    if not path.exists(next_dir):
        send_message(conn,"NOT_DIR")
    elif path.commonpath([FTP_ROOT,next_dir]) != FTP_ROOT:
        send_message(conn,"ACCESS_DENIED")
    elif path.isdir(next_dir):
        send_message(conn,"DIR_CHANGED")
        return next_dir
    else:
        send_message(conn,"DIR_NOT_FOUND") 
    return curr_dir

def cd(s, dir, port):
    """
    Changes Dir Client side
    """
    recv_message(s)
   
def help():
    """
    Shows available commands
    """


def send_message(conn, key, **kargs):

    """
    Encodes and sends a JSON message to the client, it also can send data
    """
    msg = FTP_MESSAGES.get(key)
    if kargs:
        msg.update(kargs)
    if msg:
        print(msg)
        conn.sendall(json.dumps(msg).encode())
    return msg


def send_client_message(s, full_cmd):
    """
    Encodes and sends a JSON message to the server and
    returns the created dict
    """
    cmd, *params = full_cmd.split()
    # fix el return None xq se cae
    if cmd.upper() == "SUBIR" and not path.isfile(params[0]):
        return None
    msg = {"cmd": cmd}
    if params:
        msg.update({"params": params})
    if cmd.upper() == "SUBIR":
        msg.update({"size": path.getsize(params[0])})
    s.sendall(json.dumps(msg).encode())
    return msg


def recv_sv_message(conn):
    """
    Decodes server message
    """

    data = conn.recv(BUFFER_SIZE)
    if not data:
        return None
    return json.loads(data.decode())


def recv_message(s):
    """
    Receives a json messages decodes it and print it formated code - message
    """
    data = s.recv(BUFFER_SIZE)
    message = json.loads(data.decode())
    print(f"{message['code']} - {message['message']}")
    return message


def init_autocomplete():
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
        server()
    else:
        client()
