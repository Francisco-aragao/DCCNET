import hashlib
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
        "hostport",
        metavar="host:port",
        type=str,
        help="Server host and port in the format <host>:<port>.",
    )


    parser.add_argument(
        "gas",
        metavar="GAS",
        type=str,
        help="Group Authentication Sequence. The client will use this sequence to authenticate with the grading server.",
    )

    return parser

def grading1(sock: socket.socket, gas: str):
    messageFull: str = ""

    # Step 1: Authenticate with the server
    frame: bytes = buildFrame(dccnet.currTransmitID, FLAG_EMPTY_HEX, gas.encode('ascii') + MESSAGE_TERMINATOR)

    sendFrameAndWaitForACK(sock, frame)

    # Step 2: Receive and send messages until END
    while True:
        frame: dict[str, Any] | None = receiveAndCheckFrame(sock)

        if frame is not None:
            # Grading finished, no need to send MD5
            if frame['flag'] == "END":
                logging.info("grading1: Grading 1 complete. Exiting...")
                break
            
            # Grading message received
            # Get ASCII message
            messageRecv: str = frame['dataRaw'].decode('ascii')

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

                    frameMD5: bytes = buildFrame(dccnet.currTransmitID, FLAG_EMPTY_HEX, md5.encode('ascii') + MESSAGE_TERMINATOR)

                    logging.debug(f"grading1: Sending MD5 for ID {frame['id']} with ID {dccnet.currTransmitID}. MD5 for: \"{messageFull}\"")

                    sendFrameAndWaitForACK(sock, frameMD5)

                    # Reset accumulated message
                    messageFull = ""

if __name__ == "__main__":
    # Get args and init log
    parser = initParser()
    args = parser.parse_args()

    # Find host and port in such a way that IPv6 addresses are supported
    sepIdx: int = args.hostport.rfind(':')

    host: str = args.hostport[:sepIdx]
    port: int = int(args.hostport[sepIdx+1:])

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=logging.DEBUG,
        filename="md5-client.log",
        filemode="w",
        encoding="utf-8",
    )

    sock: socket.socket = initClientConnection(host, port)
    
    grading1(sock, args.gas)

    sock.close()