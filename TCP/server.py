import socket
import threading

PORT = 4040
MESSAGE_LENGTH_SIZE = 64
ENCODING = 'utf-8'


def connect():
    address = socket.gethostbyname(socket.gethostname())
    HOST_INFORMATION = (address, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(HOST_INFORMATION)
    print("server starting ...")
    start(s)


def start(server):
    server.listen()
    while True:
        conn, address = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, address))
        t.start()


def handle_client(conn, address):
    print("[NEW CONNECTION] connected from{}".format(address))
    Connected = True
    while Connected:
        message_length = int(conn.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
        msg = conn.recv(message_length).decode(ENCODING)
        print("[MESSAGE RECEIVED] {}".format(msg))
        if msg == "DISCONNECT":
            Connected = False
    conn.close()


if __name__ == '__main__':
    connect()
