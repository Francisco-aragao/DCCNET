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
    # Note 1: only works for TCP
    # Note 2: "" means all interfaces
    try:
        if socket.has_dualstack_ipv6():
            sock = socket.create_server(("", port), family=socket.AF_INET6, dualstack_ipv6=True)
        else:
            sock = socket.create_server(("", port))
    except OSError as msg:
        logging.error(f"Attempt at creating and binding socket failed. {msg}")
        logging.error("Could not open a valid socket")
        exit(1)

    return sock

def exchangeFile(sock: socket.socket, inputFile, outputFile):
    # Stop conditions
    finishedSending: bool = False
    finishedReceiving: bool = False

    maxConsecutiveInvalidFrames: int = MIN_RETRANSMISSIONS_RETRIES

    while not finishedReceiving or not finishedSending:
        # Client starts sending frame
        if not finishedReceiving:
            frame: dict[str, Any] | None = receiveAndCheckFrame(sock)

            # Client did not send chunk or corrupted
            if frame is None:
                # We finished sending so we MUST receive something
                if finishedSending:
                    if maxConsecutiveInvalidFrames == 0:
                        logging.error(f"exchangeFile: Too many consecutive invalid or no frames received. Aborting...")
                        sendRSTAndAbort(sock)

                    attemptNum: int = MIN_RETRANSMISSIONS_RETRIES - maxConsecutiveInvalidFrames + 1
                    logging.warning(f"exchangeFile: Invalid or no frame received ({attemptNum}/{MIN_RETRANSMISSIONS_RETRIES}).")

                    maxConsecutiveInvalidFrames -= 1
                    continue
            else:
                # Valid chunk, so reset counter
                maxConsecutiveInvalidFrames = MIN_RETRANSMISSIONS_RETRIES

                # Received data frame, write to file
                outputFile.write(frame['dataRaw'])

                # Received END frame, file is complete (we may continue sending data)
                if frame['flag'] == "END":
                    logging.info("exchangeFile: Finished receiving file.")
                    finishedReceiving = True
                    continue

        # Send our frame
        if not finishedSending:
            chunk: bytes = inputFile.read(MAX_PAYLOAD_SIZE)

            if not chunk:
                # We finished sending, send END to client (we may continue receiving)
                finishedSending = True

                frame: bytes = buildFrame(dccnet.currTransmitID, FLAG_END_HEX)
                sendFrameAndWaitForACK(sock, frame)
                logging.info("exchangeFile: Finished sending file.")
                continue

            # Valid file data, send to client
            frame: bytes = buildFrame(dccnet.currTransmitID, FLAG_EMPTY_HEX, chunk)
            sendFrameAndWaitForACK(sock, frame)

    logging.info("exchangeFile: File transfer complete.")

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
    
    # SERVER OPERATION
    if args.hostport == None: # -s
        sock: socket.socket = initServerConnection(int(args.port))

        # Init file transfer
        with open(args.input, 'rb') as inputFile, open(args.output, 'wb') as outputFile:
            # Wait for connection
            conn, addr = sock.accept()

            with conn:
                logging.info(f"Connected by {addr}")
                exchangeFile(conn, inputFile, outputFile)
    # CLIENT OPERATION
    else:
        # Find host and port in such a way that IPv6 addresses are supported
        sepIdx: int = args.hostport.rfind(':')

        host: str = args.hostport[:sepIdx]
        port: int = int(args.hostport[sepIdx+1:])

        sock: socket.socket = initClientConnection(host, port)

        # Init file transfer
        with open(args.input, 'rb') as inputFile, open(args.output, 'wb') as outputFile:
            exchangeFile(sock, inputFile, outputFile)

    sock.close()