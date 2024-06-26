import socket
import logging
import time
import struct

from typing import Any

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
TIMEOUT_SEC: int = 1

BUF_SIZE: int = MAX_FRAME_SIZE * 2 # Buffering up to 2 frames is enough to find misaligned frames

MESSAGE_TERMINATOR: bytes = b'\n'

class DCCNET:
    def __init__(self):
        # Transmitter
        self.currTransmitID: int = 0
        self.lastTransmitID: int = -1
        
        # Receiver
        self.lastReceivedID: int = -1
        self.lastReceivedChksumHex: str = -1
        self.waitingForACK: bool = False
        self.receivedDataQueue: list[dict[str, Any]] = list()
    
    def nextTransmitID(self):
        self.lastTransmitID = self.currTransmitID
        self.currTransmitID = 1 if self.currTransmitID == 0 else 0

    def updateLastFrameReceived(self, frame: dict[str, Any]):
        self.lastReceivedID = frame['id']
        self.lastReceivedChksumHex = frame['checksumHex']

# Init DCCNET as global
dccnet = DCCNET()

# Adapted from: https://docs.python.org/3/library/socket.html#creating-sockets
def initClientConnection(host: str, port: int) -> socket.socket:
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

    return frame

def checkFrame(frame: bytes) -> tuple[bool, dict[str, Any]]:
    # Check if frame starts with SYNC_HEX + SYNC_HEX
    if (frame[0:8] != SYNC_HEX + SYNC_HEX):
        logging.warning(f"checkFrame: Frame does not start with SYNC_HEX + SYNC_HEX.")
        return False, dict()

    # Extract header
    checksum: int = struct.unpack('!H', frame[8:10])[0]
    length: int = struct.unpack('!H', frame[10:12])[0]
    id: int = struct.unpack('!H', frame[12:14])[0]
    flags: bytes = frame[14:15]
    
    if (length < 0 or length > MAX_PAYLOAD_SIZE):
        logging.warning(f"checkFrame: Frame has invalid length.")
        return False, dict()
    
    # If frame is misaligned, it might not have the full payload
    if (len(frame) < HEADER_SIZE + length):
        logging.warning(f"checkFrame: Frame is misaligned, length is bigger than available data.")
        return False, dict()
    
    # Extract raw data
    data: bytes = frame[HEADER_SIZE:HEADER_SIZE + length]
    
    # Extract full frame
    frameFull: bytes = frame[0:HEADER_SIZE + length]

    # Set checksum to 0 to calculate the checksum of the frame
    frameFull: bytes = frameFull[0:8] + CHKSUM_EMPTY_HEX + frameFull[10:]

    checksumCalc: int = calculateInternetChecksum(frameFull)

    if (checksum != checksumCalc):
        logging.warning(f"Check frame: Frame has invalid checksum.")
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

def sendRSTAndAbort(sock: socket.socket):
    frame: bytes = buildFrame(ID_RST, FLAG_RST_HEX)

    sock.sendall(frame)
    sock.close()

    logging.info(f"sendRSTAndAbort: Sent RST request. Connection closed. Exiting...")

    exit(0)

def sendACK(sock: socket.socket, id: int):
    frame: bytes = buildFrame(id, FLAG_ACK_HEX)

    logging.debug(f"sendACK: Sending ACK for ID {id}")

    sock.sendall(frame)

def receiveAndCheckFrame(sock: socket.socket, skipDataQueue: bool = False) -> dict[str, Any] | None:
    # Check for queued frames
    if not skipDataQueue and len(dccnet.receivedDataQueue) > 0:
        return dccnet.receivedDataQueue.pop()

    # Prepare to receive frame
    sock.settimeout(TIMEOUT_SEC)

    # Receive new frame, ignore ACKed retransmissions and duplicate ACKs
    while (True):
        try:
            response: bytes = sock.recv(BUF_SIZE)
        except socket.timeout:
            logging.warning(f"receiveAndCheckFrame: Timeout expired.")
            return None
        
        # Sync frame
        frameStartIdx: int = response.find(SYNC_HEX + SYNC_HEX)

        if frameStartIdx == -1:
            logging.warning(f"receiveAndCheckFrame: Could not sync to received data. SYNC_HEX is missing/corrupted.")
            return None

        (valid, frame) = checkFrame(response[frameStartIdx:])

        if valid:
            logging.debug(f"receiveAndCheckFrame: Received valid frame: {frame}")

            # Received RST frame, abort
            if frame['flag'] == "RST":
                logging.error(f"receiveAndCheckFrame: Received RST frame. Aborting...")

                sock.close()
                exit(0)

            # Received data frame, check for retransmitted frame
            if frame['flag'] != "ACK":
                if frame['id'] == dccnet.lastReceivedID and frame['checksumHex'] == dccnet.lastReceivedChksumHex:
                    logging.warning(f"receiveAndCheckFrame: Received duplicate data frame. Re-sending ACK and skipping...")

                    sendACK(sock, frame['id'])
                    continue

                # Update last received data frame if it's a new one, also send ACK
                sendACK(sock, frame['id'])
                dccnet.updateLastFrameReceived(frame) 

                # If we're waiting for ACK, queue this frame and continue
                if dccnet.waitingForACK:
                    dccnet.receivedDataQueue.append(frame)
                    continue

            # Received duplicate ACK frame (we are not waiting for ACK, because we have ACKed the last data frame)
            if frame['flag'] == "ACK" and not dccnet.waitingForACK:
                if frame['id'] == dccnet.lastTransmitID:
                    logging.warning(f"receiveAndCheckFrame: Received duplicate ACK frame. Skipping...")
                    continue

            # Return valid ACK frame or new data frame
            return frame

        # Received frame is invalid
        return None

def sendFrameAndWaitForACK(sock: socket.socket, frame: bytes):
    attempts: int = MIN_RETRANSMISSIONS_RETRIES

    # Check frame before sending to avoid possible misuse
    valid, frameSend = checkFrame(frame)

    if not valid:
        logging.error(f"sendFrameAndWaitForACK: Attempt to send invalid frame. Aborting...")
        sendRSTAndAbort(sock)

    logging.debug(f"sendFrameAndWaitForACK: Sending frame: {frameSend}")

    # Wait for ACK, retransmit up to MIN_RETRANSMISSIONS_RETRIES times
    dccnet.waitingForACK = True

    while attempts:
        # Send frame and check response
        sock.sendall(frame)

        frameRecv: dict[str, Any] | None = receiveAndCheckFrame(sock, True)
        
        if frameRecv is not None:
            # Got ACK for current transmitted frame
            if frameRecv['flag'] == "ACK" and frameRecv['id'] == frameSend['id']:
                logging.debug(f"sendFrameAndWaitForACK: Received ACK for ID {frameSend['id']}")

                # Finish this frame transmission
                dccnet.nextTransmitID()
                dccnet.waitingForACK = False
                return

        # checkFrame returned None, invalid frame or timeout expired
        if frameRecv is None:
            attemptNum: int = MIN_RETRANSMISSIONS_RETRIES - attempts + 1
            logging.warning(f"sendFrameAndWaitForACK: No ACK received ({attemptNum}/{MIN_RETRANSMISSIONS_RETRIES}). Retransmitting...")  

        # Retransmit
        time.sleep(RETRANSMISSION_TIME_SEC)
        attempts -= 1

    # Retransmission limit reached
    logging.error(f"sendFrameAndWaitForACK: Retransmission limit reached. Aborting...")
    sendRSTAndAbort(sock)