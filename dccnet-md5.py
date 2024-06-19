import binascii
import hashlib
from operator import length_hint
import socket
import json
import argparse
import multiprocessing
import logging
import copy as cp

import struct
from typing import Any
from itertools import repeat

# Len requisition fields (in bits)
SYNC_LEN = 32
SYNC_HEX = bytes.fromhex('DCC023C2')
FLAG_ACK_HEX = b'0x80'
FLAG_END_HEX = bytes.fromhex('40')
FLAG_RST_HEX = b'0x20'
FLAG_EMPTY_HEX = b'0x00'
ID_RST_HEX = b'0xFFFF'
CHKSUM_LEN = 16
LENGHT_LEN = 16 # should be send with big endian
MAX_PAYLOAD_SIZE = 4096
ID_LEN = 16 #should be send with big endian
FLAG_LEN = 8

CHKSUM_EMPTY = b'\x00\x00'

RETRANSMISSION_TIME_SEC = 1

MESSAGE_TERMINATOR = '\n'

MIN_RETRANSMISSIONS_RETRIES = 16

ID_0 = 0
ID_1 = 1

class DCCNet:
    """
    DCCNet class
    """

    def __init__(self):
        self.chksum = 0
        self.id = 0


def initParser() -> argparse.ArgumentParser:
    """
    Initialize the argument parser.
    """

    parser = argparse.ArgumentParser(
        description="DCCNET used in the Computer Networks course at UFMG."
    )

    parser.add_argument(
        "hostport",
        metavar="host:port",
        type=str,
        help="Server host and port in the format <host>:<port>.",
    )


    parser.add_argument(
        "gas",
        metavar="GAS",
        type=str,
        help="Group Authentication Sequence. The client will use this sequence to authenticate with the server",
    )

    return parser


# Adapted from: https://docs.python.org/3/library/socket.html#creating-sockets
def initConnection(host: str, port: int) -> socket.socket:
    """
    Create a socket connecting to host:port.

    Hostnames are resolved automatically, IPv4 and Ipv6 addresses are supported.

    An error to create a socket will cause the program to exit with code 1.

    Parameters
    ----------
    `host`: Host to connect as a string. Can be a hostname or an IPv4 or IPv6 address.
    `port`: Port to connect as a integer.

    Returns
    -------
    `socket`: A socket connected to host:port if successful.
    """

    sock = None

    # This will resolve any hostname, and check for IPv4 and IPv6 addresses
    # The first socket to get a successful connection is returned
    # Note: using SOCK_DGRAM for UDP
    for res in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
        af, socktype, proto, canonname, sa = res

        try:
            sock = socket.socket(af, socktype, proto)
        except OSError as msg:
            logging.warning(f"Attempt at creating socket failed. {msg}")

            sock = None
            continue
        try:
            sock.connect(sa)
        except OSError as msg:
            logging.warning(f"Attempt at connecting socket to {sa} failed. {msg}")

            sock.close()
            sock = None
            continue
        break

    if sock is None:
        logging.error("Could not open a valid socket")
        exit(1)

    return sock

def md5Checksum(data) -> str:

    checksum = hashlib.md5(data).hexdigest()

    return checksum

def md5Checksum2(data):

    checksum = hashlib.md5(data).digest()

    return checksum

def calculate_checksum(data):
    # Step 1: Convert data into a series of 16-bit integers
    if len(data) % 2 != 0:
        # If the length is odd, pad the data with a zero byte at the end
        data += b'\x00'
    
    checksum = 0
    
    # Step 2: Calculate the sum of all 16-bit integers
    for i in range(0, len(data), 2):
        # Combine two bytes to form a 16-bit integer
        word = (data[i] << 8) + data[i+1]
        checksum += word
        # Handle carry bit wrap around
        checksum = (checksum & 0xffff) + (checksum >> 16)
    
    # Step 3: Take the 1's complement of the final sum
    checksum = ~checksum & 0xffff
    
    return checksum

'''
TODO: TEST MD5 CHECKSUM
RECEIVE DATA FROM THE RESPONSE
SEND AUTHENTICATION CORRECTLY (FINISH BUILD FRAME REQUEST)

'''

def buildFrameRequest(id, flag, data) :

    length = struct.pack('>H', len(data))

    data = data.encode('ascii') 

    id_bin = struct.pack('>H', id)
    
    checksum = sum(SYNC_HEX + SYNC_HEX + CHKSUM_EMPTY + length + id_bin + flag + data)
    checksum = calculate_checksum(SYNC_HEX + SYNC_HEX + CHKSUM_EMPTY + length + id_bin + flag + data)
    checksum_bin = struct.pack('>H', checksum)

    print('\n Frame enviado \n')
    print('SYNC ', SYNC_HEX)
    print('Checksum ', checksum)
    print('checksum binario ', checksum_bin)
    print('length ', length)
    print('id ', id)
    print('id bin ', id_bin)
    print('flag ', flag)
    print("Data ", data)
    print()


    return SYNC_HEX + SYNC_HEX + checksum_bin + length + id_bin + flag + data

def returnResponseFormatted(response):
    sync1 = response[:4]       # First 32 bits (4 bytes)
    sync2 = response[4:8]      # Second 32 bits (4 bytes)
    checksum = response[8:10]  # Next 16 bits (2 bytes)
    len = response[10:12]  # Next 16 bits (2 bytes)
    id = response[12:14] # Next 16 bits (2 bytes)
    flags = response[14:15] # Next 8 bits (1 byte)


    checksum_int = struct.unpack('!H', checksum)[0]
    len_int = struct.unpack('>H', len)[0]
    id_int = struct.unpack('!H', id)[0]

    print('chcksum original ' , checksum)

    data = response[15:] # remaining bytes, from 15 to 15+len bytes
    data_with_no_new_line = data[:-1]

    print('Data: ', data)

    print("SOMA: ", sum(sync1 + sync2 + b'\x00\x00' + len + id + flags + data))
    print("SOMA SEM \\N ", sum(sync1 + sync2 + b'\x00\x00' + len + id + flags + data_with_no_new_line) )

    print('MD5 checksum: ', md5Checksum2(sync1 + sync2 + b'\x00\x00' + len + id + flags + data))
    print('Novo checksum: ',calculate_checksum(sync1 + sync2 + b'\x00\x00' + len + id + flags + data))

    print()
    print('Response com checksum zerado: ', sync1 + sync2 + b'\x00\x00'+ len + id + flags + data)


    return sync1.hex(), sync2.hex(), checksum_int, len_int, id_int, flags.hex(), data


def sendAuthRequest(sock, gas):

    # COMO AUTENTICAR ??

    for idx in range(0, MIN_RETRANSMISSIONS_RETRIES):
        if (idx == MIN_RETRANSMISSIONS_RETRIES-1):
            sock.close()
            raise Exception('Too many attempts, conection closed')

        try:

            frame = buildFrameRequest(ID_0, FLAG_END_HEX, gas + MESSAGE_TERMINATOR)
            #frame = buildFrameRequest(ID_0, FLAG_EMPTY_HEX,  MESSAGE_TERMINATOR)
            print()
            print("Frame enviado ", frame)

            sock.sendall(frame)

            for _ in range (1000):
                pass
            
            response = sock.recv(150) #numero aleatorio, talvez seria melhor receber a mensagme em partes, após receber o len, sei quanto preciso receber de data

            #struct.unpack('>', response)

            print('response original ', response)
            print("Response ", response.hex())

            print()
            sync, sync, checksum, len, id, flag, data = returnResponseFormatted(response)
            print("Response formatted ", (sync, sync, checksum, len, id, flag, data))

            print(data)

            print(str(data))

            raise

        except socket.timeout:
            raise Exception('Too many attempts, conection closed')



def sendPayload(
    sock: socket.socket,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Send payload to socket.

    Automatically handles packet drops when sending or receiving.

    If there is no response from the server after `MAX_ATTEMPTS`, nothing will be returned.

    #### There is a special case for requests of type `getturn`:
        - Only the first bridge data is returned.
        - If the first bridge is not present in the received data, a retransmission is made.
        - All other bridges are ignored, whether they were received or not.

    Parameters
    ----------
    `sock`: Socket with a valid connection.
    `payload`: Payload to send as a json formatted dict.

    Returns
    -------
    `result`: A json formatted dict with the response data from the server.
    """

    attempts: int = MAX_ATTEMPTS

    sock.settimeout(TIMEOUT_SEC)

    while attempts:
        res: bytes = bytes()

        try:
            sock.sendall(json.dumps(payload).encode("ascii"))

            # Try to receive as much data as possible until a timeout occurs
            while True:
                chunk: bytes = sock.recv(BUF_SIZE)
                res += chunk

        except socket.timeout:
            logging.debug(
                f"Socket connected to {sock.getsockname()}, received {len(res)} bytes in total"
            )

            if len(res) > 0:
                logging.debug(res.decode("ascii"))

                # Ensure concatenated dicts will parse properly when receiveing 'getturn' data
                # Also ensure 'getturn' got first bridge data
                if payload["type"] == "getturn":
                    res = res.replace(b"}{", b"},\n{")
                    res = b"[" + res + b"]"

                    resDict: list[dict[str, Any]] = json.loads(res)

                    # Got first bridge or game over
                    if resDict[0]["type"] == "gameover" or resDict[0]["bridge"] == 1:
                        return resDict[0]

                elif payload["type"] == "shot":
                    # Ensure concatenated dicts will parse properly when receiveing multiple 'shots' data
                    res = res.replace(b"}{", b"},\n{")
                    res = b"[" + res + b"]"

                    return json.loads(res)

                else:
                    # For other payload types, just return parsed data
                    return json.loads(res)

            # If no data was received at all or an error occurred, retransmit
            attempts -= 1

        except OSError as msg:
            logging.error(
                f"Socket connected to {sock.getsockname()}, could not send and/or receive data. {msg}"
            )

    # No data received after TIMEOUT_SEC * attempts
    return dict()




if __name__ == "__main__":
    # Get args and init log
    parser = initParser()
    args = parser.parse_args()

    host, port = args.hostport.split(":")
    port = int(port)

    print(host)
    print(port)

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=logging.DEBUG,
        filename="client.log",
        filemode="w",
        encoding="utf-8",
    )

    sock = initConnection(host, port)

    
    # Step 1: Begin authentication
    res = sendAuthRequest(sock, args.gas)

    sock.close()

    raise

    for r in res:
        if r["status"] != 0:
            logging.error(f"Authentication failed with a server. Aborted")
            exit(1)
