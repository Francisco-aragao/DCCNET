import socket
import argparse
import logging

from typing import Any

from dccnetcommon import *

def initParser() -> argparse.ArgumentParser:
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
        help="Server port to listen to.",
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
        help="File to send to remote end of the link",
    )

    parser.add_argument(
        "output",
        metavar="output",
        type=str,
        help="File to receive from remote end of the link",
    )

    return parser

# Adapted from: https://docs.python.org/3/library/socket.html#creating-sockets
def initServerConnection(port: int) -> socket.socket:
    """
    Create a socket listening on port.

    An error to create a socket will cause the program to exit with code 1.

    Parameters
    ----------
    `port`: Port to listen to.

    Returns
    -------
    `socket`: A socket listening on port if successful.
    """

    # This will try to listen on IPv4 and IPv6 addresses
    # The first socket to get a successful connection is returned
    # Note: using TCP protocol for DCCNET
    for res in socket.getaddrinfo(None, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP, flags=socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res

        try:
            sock = socket.socket(af, socktype, proto)
        except OSError as msg:
            logging.warning(f"Attempt at creating socket failed. {msg}")

            sock = None
            continue
        try:
            sock.bind(sa)
            sock.listen(1)                       
        except OSError as msg:
            logging.warning(f"Attempt at binding socket to {sa} failed. {msg}")

            sock.close()
            sock = None
            continue
        break

    if sock is None:
        logging.error("Could not open a valid socket")
        exit(1)

    return sock

def serverExchangeFile(sock: socket.socket, inputFile, outputFile):
    # Stop conditions
    finishedSending: bool = False
    finishedReceiving: bool = False

    maxConsecutiveInvalidFrames: int = MIN_RETRANSMISSIONS_RETRIES

    # Wait for connection
    conn, addr = sock.accept()

    with conn:
        logging.info(f"Connected by {addr}")

        while not finishedReceiving or not finishedSending:
            # Client starts sending frame
            if not finishedReceiving:
                frame: dict[str, Any] | None = receiveAndCheckFrame(conn)

                if frame is None:
                    if maxConsecutiveInvalidFrames == 0:
                        logging.error(f"serverExchangeFile: Too many consecutive invalid frames received. Aborting...")
                        sendRSTAndAbort(conn)

                    logging.warning(f"serverExchangeFile: Received invalid frame. Skipping...")

                    maxConsecutiveInvalidFrames -= 1
                    continue
                else:
                    maxConsecutiveInvalidFrames = MIN_RETRANSMISSIONS_RETRIES

                # Received data frame, write to file
                outputFile.write(frame['dataRaw'])

                # Send ACK for received frame
                sendACK(conn, frame['id'])

                # Received END frame, file is complete (we may continue sending data)
                if frame['flag'] == "END":
                    finishedReceiving = True
                    continue

            # Send our frame
            if not finishedSending:
                chunk: bytes = inputFile.read(MAX_PAYLOAD_SIZE)

                if not chunk:
                    # We finished sending, send END to client (we may continue receiving)
                    finishedSending = True

                    frame: bytes = buildFrame(dccnet.currTransmitID, FLAG_END_HEX)
                    sendFrameAndWaitForACK(conn, frame)
                    continue

                # Valid file data, send to client
                frame: bytes = buildFrame(dccnet.currTransmitID, FLAG_EMPTY_HEX, chunk)
                sendFrameAndWaitForACK(conn, frame)

def clientExchangeFile(sock: socket.socket, inputFile, outputFile):
    # Stop conditions
    finishedSending: bool = False
    finishedReceiving: bool = False

    maxConsecutiveInvalidFrames: int = MIN_RETRANSMISSIONS_RETRIES

    while not finishedReceiving or not finishedSending:
        # We start sending frame
        if not finishedSending:
            chunk: bytes = inputFile.read(MAX_PAYLOAD_SIZE)

            if not chunk:
                # We finished sending, send END to client (we may continue receiving)
                finishedSending = True

                frame: bytes = buildFrame(dccnet.currTransmitID, FLAG_END_HEX)
                sendFrameAndWaitForACK(sock, frame)
                continue

            # Valid file data, send to client
            frame: bytes = buildFrame(dccnet.currTransmitID, FLAG_EMPTY_HEX, chunk)
            sendFrameAndWaitForACK(sock, frame)

        if not finishedReceiving:
            frame: dict[str, Any] | None = receiveAndCheckFrame(sock)

            if frame is None:
                if maxConsecutiveInvalidFrames == 0:
                    logging.error(f"serverExchangeFile: Too many consecutive invalid frames received. Aborting...")
                    sendRSTAndAbort(sock)

                logging.warning(f"serverExchangeFile: Received invalid frame. Skipping...")

                maxConsecutiveInvalidFrames -= 1
                continue
            else:
                maxConsecutiveInvalidFrames = MIN_RETRANSMISSIONS_RETRIES

            # Received data frame, write to file
            outputFile.write(frame['dataRaw'])

            # Send ACK for received frame
            sendACK(sock, frame['id'])

            # Received END frame, file is complete (we may continue sending data)
            if frame['flag'] == "END":
                finishedReceiving = True
                continue

if __name__ == "__main__":
    parser = initParser()
    args = parser.parse_args()

    # Change log filename to match the current run
    logFileName: str = "xfer-client.log"

    if args.hostport == None:
        logFileName = "xfer-server.log"

    # Get args and init log
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=logging.DEBUG,
        filename=logFileName,
        filemode="w",
        encoding="utf-8",
    )

    if args.hostport == None: # -s
        sock: socket.socket = initServerConnection(int(args.port))

        # Init file transfer
        with open(args.input, 'rb') as inputFile, open(args.output, 'wb') as outputFile:
            serverExchangeFile(sock, inputFile, outputFile)
    else:
        # Find host and port in such a way that IPv6 addresses are supported
        sepIdx: int = args.hostport.rfind(':')

        host: str = args.hostport[:sepIdx]
        port: int = int(args.hostport[sepIdx+1:])

        sock: socket.socket = initClientConnection(host, port)

        # Init file transfer
        with open(args.input, 'rb') as inputFile, open(args.output, 'wb') as outputFile:
            clientExchangeFile(sock, inputFile, outputFile)

    sock.close()