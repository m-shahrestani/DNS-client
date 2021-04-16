# part 2-3
import socket

local_address = ("127.0.0.1", 20001)
bufferSize = 4096

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind(local_address)
print("UDP server up and listening")

while True:
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    clientMsg = "Message from Client: " + message.decode()
    clientIP = "Client IP Address:{}".format(address)
    msgFromServer = "UDP Client your massage is: " + message.decode()
    bytesToSend = str.encode(msgFromServer)
    print(clientMsg)
    print(clientIP)
    UDPServerSocket.sendto(bytesToSend, address)
