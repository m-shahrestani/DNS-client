import socket

PORT = 4040
MESSAGE_LENGTH_SIZE = 64
ENCODING = 'utf-8'


def connect():
    address = socket.gethostbyname(socket.gethostname())
    SERVER_INFORMATION = (address, PORT)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(SERVER_INFORMATION)
    send_msg(c, "Hello")
    send_msg(c, "DISCONNECT")


def send_msg(client, msg):
    message = msg.encode(ENCODING)
    msg_length = len(message)
    msg_length = str(msg_length).encode(ENCODING)
    msg_length += b' ' * (MESSAGE_LENGTH_SIZE - len(msg_length))
    client.send(msg_length)
    client.send(message)


if __name__ == '__main__':
    connect()
