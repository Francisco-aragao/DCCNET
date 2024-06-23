import binascii
import hashlib
from operator import length_hint
import socket
import json
import argparse
import multiprocessing
import logging
import copy as cp
import time

import struct
from typing import Any
from itertools import repeat

# DCCNET frame specifications
SYNC_HEX: bytes = bytes.fromhex('DCC023C2')

FLAG_ACK_HEX: bytes = bytes.fromhex('80')
FLAG_END_HEX: bytes = bytes.fromhex('40')
FLAG_RST_HEX: bytes = bytes.fromhex('20')
FLAG_EMPTY_HEX: bytes = bytes.fromhex('00')

ID_RST: int = 65535
CHKSUM_EMPTY_HEX: bytes = bytes.fromhex('0000')

SYNC_LEN_BYTES: int = 4
CHKSUM_LEN_BYTES: int = 2
LENGTH_LEN_BYTES: int = 2 # should be sent as big endian
ID_LEN_BYTES: int = 2 # should be sent as big endian
FLAG_LEN_BYTES: int = 1

MAX_PAYLOAD_SIZE: int = 4096
HEADER_SIZE: int = SYNC_LEN_BYTES * 2 + CHKSUM_LEN_BYTES + LENGTH_LEN_BYTES + ID_LEN_BYTES + FLAG_LEN_BYTES
MAX_FRAME_SIZE: int = MAX_PAYLOAD_SIZE + HEADER_SIZE

# SEND/RECEIVE parameters
RETRANSMISSION_TIME_SEC: int = 1
MIN_RETRANSMISSIONS_RETRIES: int = 16
TIMEOUT_SEC: int = 0.5

BUF_SIZE: int = MAX_FRAME_SIZE * 2 # Buffering up to 2 frames is enough to find misaligned frames
RECV_BUFFER: bytes = bytes()

# Keep track of the current and last TX/RX ID
CURR_TRANSMITTED_ID: int = 0

LAST_RECEIVED_ID: int = 0
LAST_RECEIVED_CHKSUM: bytes = CHKSUM_EMPTY_HEX

MESSAGE_TERMINATOR: bytes = b'\n'

def initParser() :
    """
    Initialize the argument parser.
    """

    parser = argparse.ArgumentParser(
        description="DCCNET used in the Computer Networks course at UFMG."
    )

    parser.add_argument(
        "-s",
        "--port",
        metavar="port",
        type=str,
        help="Server port.",
    )


    parser.add_argument(
        "-c",
        "--hostport",
        metavar="host:port",
        type=str,
        help="Server host and port in the format <host>:<port>.",
    )


    parser.add_argument(
        "input",
        metavar="input",
        type=str,
        help="Name of a file with the data that will be sent to the remote end of the link",
    )

    parser.add_argument(
        "output",
        metavar="output",
        type=str,
        help="Name of a file where the data received from the remote end of the link will be stored",
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
    # Note: using TCP protocol for DCCNET
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

def listenForConnections(port: int) -> socket.socket:
    """
    Create a socket listening on port.

    An error to create a socket will cause the program to exit with code 1.

    Parameters
    ----------
    `port`: Port to listen as a integer.

    Returns
    -------
    `socket`: A socket listening on port if successful.
    """

    HOST = ''                 # Symbolic name meaning all available interfaces
    PORT = 64646              # Arbitrary non-privileged port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data: break
                conn.sendall(data)

    sock = None

    # This will resolve any hostname, and check for IPv4 and IPv6 addresses
    # The first socket to get a successful connection is returned
    # Note: using TCP protocol for DCCNET
    for res in socket.getaddrinfo(None, port, proto=socket.IPPROTO_TCP, flags=socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res

        try:
            sock = socket.socket(af, socktype, proto)
        except OSError as msg:
            logging.warning(f"Attempt at creating socket failed. {msg}")

            sock = None
            continue
        try:
            print(sa)
            sock.bind(('', sa[1]))
            sock.listen(1)

            conn, addr = sock.accept()
            
            
            print('Connected by', addr)
            
        except OSError as msg:
            print("erro")
            logging.warning(f"Attempt at binding socket to {sa} failed. {msg}")

            sock.close()
            sock = None
            continue
        break

    if sock is None:
        logging.error("Could not open a valid socket")
        exit(1)

    return sock

def calculateInternetChecksum(data: bytes):
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

def byteFlagToStr(flags: bytes) -> str:
    if (flags == FLAG_ACK_HEX):
        return "ACK"
    
    if (flags == FLAG_END_HEX):
        return "END"
    
    if (flags == FLAG_RST_HEX):
        return "RST"
    
    if (flags == FLAG_EMPTY_HEX):
        return "EMPTY"

    # Corrupted frame
    return "ERR"

def buildFrame(id: int, flags: bytes, data: bytes = bytes()) -> bytes:
    length = struct.pack('!H', len(data))
    idBin = struct.pack('!H', id)
    
    checksum = calculateInternetChecksum(SYNC_HEX + SYNC_HEX + CHKSUM_EMPTY_HEX + length + idBin + flags + data)
    checksumBin = struct.pack('!H', checksum)

    frame: bytes = SYNC_HEX + SYNC_HEX + checksumBin + length + idBin + flags + data

    # Debug info
    logging.debug(f"buildFrame: Built frame with {len(frame)} bytes:")

    logging.debug(f"SYNC: {SYNC_HEX.hex()}")
    logging.debug(f"SYNC: {SYNC_HEX.hex()}")
    logging.debug(f"Checksum: {hex(checksum)}")
    logging.debug(f"Length: {len(data)}")
    logging.debug(f"ID: {id}")
    logging.debug(f"Flags: {byteFlagToStr(flags)}")
    logging.debug(f"Data HEX: {data.hex()}")
    logging.debug(f"Data ASCII: {data.decode('ascii')}\n")

    return frame

# This assumes frame has arbitrary length AND starts with SYNC_HEX + SYNC_HEX
def checkFrame(sock: socket.socket, frame: bytes) -> tuple[bool, dict[str, Any]]:
    # Check if frame starts with SYNC_HEX + SYNC_HEX
    if (frame[0:8] != SYNC_HEX + SYNC_HEX):
        logging.error(f"Check frame: frame does not start with SYNC_HEX + SYNC_HEX. Unrecoverable error. Aborting...")
        sendResetRequest(sock)

    # Extract header
    checksum: int = struct.unpack('!H', frame[8:10])[0]
    length: int = struct.unpack('!H', frame[10:12])[0]
    id: int = struct.unpack('!H', frame[12:14])[0]
    flags: bytes = frame[14:15]
    
    if (length < 0 or length > MAX_PAYLOAD_SIZE):
        logging.warning(f"Check frame: frame has invalid length.")
        return False, dict()
    
    # If frame is misaligned, it might not have the full payload
    if (len(frame) < HEADER_SIZE + length):
        logging.warning(f"Check frame: frame is misaligned, length is bigger than available data.")
        return False, dict()
    
    # Extract raw data
    data: bytes = frame[HEADER_SIZE:HEADER_SIZE + length]
    
    # Extract full frame
    frameFull: bytes = frame[0:HEADER_SIZE + length]

    # Set checksum to 0 to calculate the checksum of the frame
    frameFull: bytes = frameFull[0:8] + CHKSUM_EMPTY_HEX + frameFull[10:]

    checksumCalc: int = calculateInternetChecksum(frameFull)

    if (checksum != checksumCalc):
        logging.warning(f"Check frame: frame has invalid checksum.")
        return False, dict()
    
    # Build frame data dict
    frameData: dict[str, Any] = dict()

    frameData['checksumHex'] = hex(checksum)
    frameData['length'] = length
    frameData['lengthFull'] = length + HEADER_SIZE
    frameData['id'] = id
    frameData['flag'] = byteFlagToStr(flags)
    frameData['dataRaw'] = data

    # Valid frame, carry on
    return True, frameData

def sendResetRequest(sock: socket.socket):
    frame: bytes = buildFrame(ID_RST, FLAG_RST_HEX)

    sock.sendall(frame)
    sock.close()

    logging.info(f"Sent RST request. Connection closed. Exiting...")

    exit(0)

def sendACK(sock: socket.socket, id: int):
    frame: bytes = buildFrame(id, FLAG_ACK_HEX)

    sock.sendall(frame)

def sendFrameAndWaitForACK(sock: socket.socket, frame: bytes):
    sock.sendall(frame)

    global CURR_TRANSMITTED_ID

    # Wait for ACK, retransmit up to MIN_RETRANSMISSIONS_RETRIES times
    attempts: int = MIN_RETRANSMISSIONS_RETRIES

    # sock.settimeout(TIMEOUT_SEC)

    while attempts:
        try:
            res: bytes = sock.recv(BUF_SIZE)

            # TODO TEST SYNC LATER (APPARENTLY WORKING) print(res.decode('ascii'))
            
            # Sync frame
            frameStartIdx: int = res.find(SYNC_HEX + SYNC_HEX) # TODO: maybe deal with misaligned frames, partial frames

            (valid, frameRecv) = checkFrame(sock, res[frameStartIdx:])

            if (valid):
                logging.debug(f"sendFrameAndWaitForACK: Received valid frame: {frameRecv}")

                # Got ACK for last transmitted frame
                if frameRecv['flag'] == "ACK" and frameRecv['id'] == CURR_TRANSMITTED_ID:
                    CURR_TRANSMITTED_ID = 1 if CURR_TRANSMITTED_ID == 0 else 0
                    return

            logging.warning(f"sendFrameAndWaitForACK: Received invalid frame: {res.decode('ascii')}")

            raise Exception('Invalid frame received')
        except Exception:
            # Retransmit
            time.sleep(RETRANSMISSION_TIME_SEC)

            sock.sendall(frame)
            attempts -= 1


def grading2(sock: socket.socket, gas: str):
    global CURR_TRANSMITTED_ID

    messageFull: str = ""

    # Step 1: Authenticate with the server
    frame: bytes = buildFrame(CURR_TRANSMITTED_ID, FLAG_EMPTY_HEX, gas.encode('ascii') + MESSAGE_TERMINATOR)

    sendFrameAndWaitForACK(sock, frame)

    # Step 2: Receive and send messages until END
    while True:
        res: bytes = sock.recv(BUF_SIZE)

        idx: int = res.find(SYNC_HEX + SYNC_HEX)

        (valid, data) = checkFrame(sock, res[idx:])

        if (valid):
            logging.debug(f"grading1: Received valid frame: {data}")

            # Skip multiple ACKs received
            if data['flag'] == "ACK":
                logging.debug(f"grading1: Duplicate ACK. Skipping...")
                continue
            
            # Send ACK for received frame
            sendACK(sock, data['id'])

            logging.debug(f"Sent ACK for ID {data['id']} with ID {data['id']}")

            # Grading finished, no need to send MD5
            if data['flag'] == "END":
                logging.info("Grading 1 complete. Exiting...")
                break
            
            # Get ASCII message
            messageRecv: str = data['dataRaw'].decode('ascii')

            # Partial message, concatenate with previous partial message
            if not '\n' in messageRecv:
                messageFull += messageRecv
            else:
            # Full or multiple messages
                splitMessages: list[str] = messageRecv.split('\n')

                # Finish partial message or just send full message
                for msg in splitMessages:
                    if len(msg) == 0:
                        continue

                    messageFull += msg

                    # Build MD5 frame
                    md5: str = hashlib.md5(messageFull.encode('ascii')).hexdigest()

                    frameMD5: bytes = buildFrame(CURR_TRANSMITTED_ID, FLAG_EMPTY_HEX, md5.encode('ascii') + MESSAGE_TERMINATOR)

                    logging.debug(f"Sent MD5 for ID {data['id']} with ID {CURR_TRANSMITTED_ID}. Message: \"{messageFull}\"")

                    sendFrameAndWaitForACK(sock, frameMD5)

                    # Reset accumulated message
                    messageFull = ""

if __name__ == "__main__":
    # Get args and init log

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=logging.DEBUG,
        filename="client.log",
        filemode="w",
        encoding="utf-8",
    )

    parser = initParser()
    args = parser.parse_args()

    if args.hostport == None: # -s
        sock = listenForConnections(args.port)
    else:
        sock = initConnection(args.hostport.split(':')[0], int(args.hostport.split(':')[1]))
    
    print(sock)
    
    while(True):
        pass

    raise
    grading2(sock, args.gas)

    sock.close()