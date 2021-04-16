import binascii
import csv
import socket

dnsIP = "198.41.0.4"  # root server A
local_address = ("127.0.0.1", 20001)
bufferSize = 4096
cache = {}
cache_count = {}


# part 2-1 & 2-2 & 2-3
def send_message_to_local_server(server_address, msg):
    bytesToSend = str.encode(msg)
    UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPClientSocket.sendto(bytesToSend, server_address)
    msgFromServer, _ = UDPClientSocket.recvfrom(bufferSize)
    UDPClientSocket.close()
    return msgFromServer


# part 3-1
def send_message_to_dns_server(addr, req):
    req = req.replace(" ", "").replace("\n", "")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(binascii.unhexlify(req), (addr, 53))
        data, _ = sock.recvfrom(4096)
    except:
        return None
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


# part 3-1
def build_message(address="", rec_flag=1):
    #                      HEADER
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    ID = 0  # identifier (0-65535)              16bit
    QR = 0  # Query: 0, Response: 1              1bit
    OPCODE = 0  # Standard query                 4bit
    AA = 0  # ?                                  1bit
    TC = 0  # Message is truncated?              1bit
    RD = rec_flag  # Recursion?                  1bit
    RA = 0  # ?                                  1bit
    Z = 0  # ?                                   3bit
    RCODE = 0  # ?                               4bit
    QDCOUNT = 1  # Number of questions          16bit
    ANCOUNT = 0  # Number of answers            16bit
    NSCOUNT = 0  # Number of authority records  16bit
    ARCOUNT = 0  # Number of additional records 16bit
    query_params = str(QR) + str(OPCODE).zfill(4) + str(AA) + str(TC) + str(RD) + str(RA) + str(Z).zfill(3) + str(
        RCODE).zfill(4)
    header = ""
    header = header + "{:04x}".format(ID)
    header = header + "{:04x}".format(int(query_params, 2))
    header = header + "{:04x}".format(QDCOUNT)
    header = header + "{:04x}".format(ANCOUNT)
    header = header + "{:04x}".format(NSCOUNT)
    header = header + "{:04x}".format(ARCOUNT)

    #                      Question
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                                               |
    # /                     QNAME                     /
    # /                                               /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QTYPE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QCLASS                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # QNAME is url split up by '.', preceded by int indicating length of part
    question = ""
    addr_parts = address.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        question = question + addr_len
        question = question + addr_part.decode()
    question = question + "00"  # Terminating bit for QNAME
    QTYPE = "{:04x}".format(1)  # Type of request. 1 is A
    QCLASS = 1  # Class for lookup. 1 is Internet
    question = question + QTYPE
    question = question + "{:04x}".format(QCLASS)
    return header + question


# 3-1 +
def write_to_csv(name, value):
    csv.register_dialect('myDialect', delimiter='|', quoting=csv.QUOTE_ALL)
    with open('names.csv', 'a', newline='') as file:
        writer = csv.writer(file, dialect='myDialect')
        writer.writerow([name, value])


# 3-3
def skip_name(message, start):
    end = start
    while True:
        if int(message[end:end + 2], 16) == 0:
            return end + 2
        if (int(message[end:end + 2], 16) & 0xc0) == 0xc0:
            return end + 4
        end += 2 * (int(message[end:end + 2], 16) + 1)
    return end


# 3-3
def read_dns(message, start):
    end = start
    end = skip_name(message, end)
    TYPE = int(message[end:end + 4], 16)
    end += 4
    CLASS = int(message[end:end + 4], 16)
    end += 4
    TTL = int(message[end:end + 8], 16)
    end += 8
    RDLENGTH = int(message[end:end + 4], 16)
    end += 4
    RDATA = message[end:end + 2 * RDLENGTH]
    end += 2 * RDLENGTH
    return TYPE, CLASS, TTL, RDLENGTH, RDATA, end


# 3-3 & 4
def find(name_addr, server, rec_flag):
    if server in seen:
        return False, "not found."
    seen.add(server)
    message = send_message_to_dns_server(server, build_message(address=name_addr, rec_flag=rec_flag))
    if message is None:
        return False, "not found."

    # ID = message[0:4]
    # query_params = message[4:8]
    QDCOUNT = int(message[8:12], 16)   # Number of questions
    ANCOUNT = int(message[12:16], 16)  # Number of answers
    NSCOUNT = int(message[16:20], 16)  # Number of authority records
    ARCOUNT = int(message[20:24], 16)  # Number of additional records
    question_end = 24
    for i in range(QDCOUNT):
        question_end = skip_name(message, 24)
        question_end += 2 * 2  # QTYPE
        question_end += 2 * 2  # QCLASS
    if ANCOUNT > 0:
        TYPE, CLASS, TTL, RDLENGTH, RDATA, end = read_dns(message, question_end)
        ip1 = int(RDATA[0:2], 16)
        ip2 = int(RDATA[2:4], 16)
        ip3 = int(RDATA[4:6], 16)
        ip4 = int(RDATA[6:8], 16)
        return True, "{}.{}.{}.{}".format(ip1, ip2, ip3, ip4)
    ns_end = question_end
    for i in range(NSCOUNT):
        _, _, _, _, _, ns_end = read_dns(message, ns_end)
    addition_end = ns_end
    for i in range(ARCOUNT):
        TYPE, CLASS, TTL, RDLENGTH, RDATA, addition_end = read_dns(message, addition_end)
        if TYPE == 1:
            ip1 = int(RDATA[0:2], 16)
            ip2 = int(RDATA[2:4], 16)
            ip3 = int(RDATA[4:6], 16)
            ip4 = int(RDATA[6:8], 16)
            can, final_ip = find(name_addr, "{}.{}.{}.{}".format(ip1, ip2, ip3, ip4), rec_flag)
            if can:
                return True, final_ip
    return False, "not found"


# part 2 & 3 & 4 & 5
if __name__ == "__main__":
    while True:
        inp = input()
        localServerResponse = send_message_to_local_server(local_address, inp)
        print(localServerResponse.decode())
        if inp in cache_count:
            cache_count[inp] += 1
        else:
            cache_count[inp] = 1
        if cache_count[inp] > 3:
            print("Cache:\n" + cache[inp])
        else:
            seen = set()
            _, ip = find(inp, dnsIP, 1)
            print("Recursive:\n" + ip)
            seen = set()
            _, ip = find(inp, dnsIP, 0)
            print("Iterative:\n" + ip)
            if cache_count[inp] == 3:
                cache[inp] = ip
            write_to_csv(inp, ip)
