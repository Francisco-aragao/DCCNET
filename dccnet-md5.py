import binascii
import hashlib
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
SYNC_HEX = b'0xDCC023c2'
FLAG_ACK_HEX = b'0x80'
FLAG_END_HEX = b'0x40'
FLAG_RST_HEX = b'0x20'
ID_RST_HEX = b'0xFFFF'
CHKSUM_LEN = 16
LENGHT_LEN = 16 # should be send with big endian
MAX_PAYLOAD_SIZE = 4096
ID_LEN = 16 #should be send with big endian
FLAG_LEN = 8
RETRANSMISSION_TIME_SEC = 1

MESSAGE_TERMINATOR = '\n'

MIN_RETRANSMISSIONS_RETRIES = 16

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
        print(res)
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

def calculate_md5_checksum(data):

    md5 = hashlib.md5()
    md5.update(data)
    return md5.digest()

'''
TODO: TEST MD5 CHECKSUM
RECEIVE DATA FROM THE RESPONSE
SEND AUTHENTICATION CORRECTLY (FINISH BUILD FRAME REQUEST)

'''

def buildFrameRequest(length, id, flag, data) :

    return
    return SYNC_HEX + SYNC_HEX + struct.pack('!H', length) + struct.pack('!I', id)

def returnRespondeFormatted(response):
    sync1 = response[:4]       # First 32 bits (4 bytes)
    sync2 = response[4:8]      # Second 32 bits (4 bytes)
    checksum = response[8:10]  # Next 16 bits (2 bytes)
    len = response[10:12]  # Next 16 bits (2 bytes)
    id = response[12:14]
    flags = response[14:15]

    checksum_int = struct.unpack('!H', checksum)[0]
    len_int = struct.unpack('!H', len)[0]
    id_int = struct.unpack('!H', id)[0]

    return sync1.hex(), sync2.hex(), checksum_int, len_int, id_int, flags.hex()



def sendAuthRequest(sock, gas):

    # COMO AUTENTICAR ??

    for idx in range(0, MIN_RETRANSMISSIONS_RETRIES):
        if (idx == MIN_RETRANSMISSIONS_RETRIES-1):
            sock.close()
            raise Exception('Too many attempts, conection closed')

        try:
            print('sync ' , buildFrameRequest(None, None, None, None))

            sock.sendall((gas + '\n').encode("ascii"))
            
            response = sock.recv(120)

            #struct.unpack('>', response)

            print(response.hex())

            print()
            print(returnRespondeFormatted(response))
            
            raise
            loop_until_receive_response = 0

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
