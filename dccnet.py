import socket
import json
import argparse
import multiprocessing
import logging
import copy as cp

from typing import Any
from itertools import repeat

# Board size
NUM_RIVERS = 4
NUM_BRIDGES = 8

BUF_SIZE = 4096  # Buffer size for server response.
TIMEOUT_SEC = 0.08  # Timeout in seconds when sending/receiving data.
MAX_ATTEMPTS = 8  # Max retransmission attempts when no data is received.



class GameState:
    """
    GameState class.

    Holds information about the current game.

    Variables
    ----------
    `board`: A matrix of shape [bridges, rivers]. This matrix MUST be indexed starting from 1. [1-8, 1-4]. \n
    Each entry in this matrix is a list of dicts, each dict is a ship at that position. \n
    #### Note that multiple ships can be at the same position.
    `cannons`: A list of cannons, each as a tuple (bridge, river)
    `turn`: Current turn, starts at 0.
    """

    def __init__(self):
        self.board: list[list[list[dict[str, Any]]]] = [
            [list() for _ in range(NUM_RIVERS + 1)] for _ in range(NUM_BRIDGES + 1)
        ]
        self.cannons: list[tuple[int, int]] = None
        self.turn: int = 0


def initParser() -> argparse.ArgumentParser:
    """
    Initialize the argument parser.
    """

    parser = argparse.ArgumentParser(
        description="Bridge Defense game client used in the Computer Networks course at UFMG."
    )

    parser.add_argument(
        "host",
        metavar="host",
        type=str,
        help="Game server host, as an IPv4/IPv6 address or as a hostname",
    )

    parser.add_argument(
        "port",
        metavar="port",
        type=int,
        help="Game servers initial port. The client will connect to servers at ports [port, port+1, port+2, port+3]",
    )

    parser.add_argument(
        "gas",
        metavar="GAS",
        type=str,
        help="Group Authentication Sequence. The client will use this sequence to authenticate with the game servers",
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

    sock: socket.socket = None

    # This will resolve any hostname, and check for IPv4 and IPv6 addresses
    # The first socket to get a successful connection is returned
    # Note: using SOCK_DGRAM for UDP

    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.IPPROTO_TCP):
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


def sendMultiPayload(
    sockets: list[socket.socket],
    payloads: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Send multiple payloads to multiple sockets in parallel.

    This function spawns `len(sockets)` processes.

    Lists `sockets` and `payloads` MUST have the same size.

    Automatically handles packet drops when sending or receiving.

    If there is no response from the server after `MAX_ATTEMPTS`, nothing will be returned.

    There is a special case for requests of type `getturn`:
        - Only the first bridge data is returned.
        - If the first bridge is not present in the received data, a retransmission is made.
        - All other bridges are ignored, whether they were received or not.

    Parameters
    ----------
    `sockets`: List of sockets with valid connections.
    `payloads`: List of payloads as json formatted dicts to send to each socket. First payload is sent to first socket and so on

    Returns
    -------
    `results`: A list of json formatted dicts with the response data from each server.
    """

    results: list[dict[str, Any]] = list()

    with multiprocessing.Pool() as pool:
        results = pool.starmap(sendPayload, zip(sockets, payloads))

    return results


def sendAuthenticationRequest(
    sockets: list[socket.socket], gas: str
) -> list[dict[str, Any]]:
    """
    Send an authentication request to *each* game server.

    Parameters
    ----------
    `sockets`: List of game server sockets.
    `gas`: Group Authentication Sequence.

    Returns
    -------
    `results`: A list of dicts with the response data from each server.
    """

    payload: dict[str, Any] = {"type": "authreq", "auth": gas}

    return sendMultiPayload(sockets, repeat(payload, len(sockets)))


def sendGetCannonRequest(sock: socket.socket, gas: str) -> dict[str, Any]:
    """
    Send a get cannons request to a server.

    Parameters
    ----------
    `sock`: Game server socket.
    `gas`: Group Authentication Sequence.

    Returns
    -------
    `cannons`: A dict with the response data from the server.
    """

    payload: dict[str, Any] = {"type": "getcannons", "auth": gas}

    return sendPayload(sock, payload)


def sendGameTerminationRequest(sock: socket.socket, gas: str) -> dict[str, Any]:
    """
    Send a request to end the game to a server.

    Parameters
    ----------
    `sock`: Game server socket.
    `gas`: Group Authentication Sequence.

    Returns
    -------
    `gameover`: A dict with the response data from the server.
    """

    payload: dict[str, Any] = {"type": "quit", "auth": gas}

    return sendPayload(sock, payload)


def sendTurnStateRequestFirstBridge(
    sockets: list[socket.socket], gas: str, turn: int
) -> list[dict[str, Any]]:
    """
    Send a turn state request to *each* game server.

    This function returns ONLY the state of the first bridge.\n
    The Game State for the other bridges should be kept locally.

    Parameters
    ----------
    `sockets`: List of game server sockets.
    `gas`: Group Authentication Sequence.
    `turn`: Turn to get state from.

    Returns
    -------
    `stateFirstBridge`: A list of first bridge states per river.
    """

    payload: dict[str, Any] = {"type": "getturn", "auth": gas, "turn": turn}

    return sendMultiPayload(sockets, repeat(payload, len(sockets)))


def sendMultiShotRequest(
    socketsQueue: list[socket.socket], payloadsQueue: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Send multiple shot requests in parallel.

    ### Note
    We can't send multiple requests to the same socket because of data races when receiving.

    So instead, we send a single shot request to every river in parallel until every shot is sent.

    #### Effectively, we are parallelizing shots by river but not parallelizing shots for the same river.

    Parameters
    ----------
    `socketsQueue`: List of sockets with valid connections (may repeat sockets).
    `payloadsQueue`: List of payloads as json formatted dicts to send to each socket.

    Returns
    -------
    `results`: A list of json formatted dicts with the response data from each server.
    """

    res: list[dict[str, Any]] = list()

    while len(socketsQueue) > 0:
        sockets: list[socket.socket] = list()
        payloads: list[dict[str, Any]] = list()

        for s, p in list(zip(socketsQueue, payloadsQueue)):
            if s not in sockets:
                sockets.append(s)
                payloads.append(p)

                socketsQueue.remove(s)
                payloadsQueue.remove(p)

        res.extend(sendMultiPayload(sockets, payloads))

    return res


def runGame(sockets: list[socket.socket], gas: str, game: GameState):
    """
    Run the game turn by turn:
        - Decide which cannons to shoot and where to shoot.
        - Fire cannons locally.
        - Send request to fire cannons.
        - Request first bridge state for the next turn.
        - Advance turn.
        - Repeat until gameover.

    Parameters
    ----------

    `sockets`: List of game server sockets.
    `gas`: Group Authentication Sequence.
    `game`: Game State class.
    """

    while True:
        logging.info(f"Playing turn {game.turn}")

        # Queue shots, fire cannons in parallel
        socketsQueue: list[socket.socket] = list()
        payloadsQueue: list[dict[str, Any]] = list()

        for cannon in game.cannons:
            possibleTargets: list[tuple[int, dict[str, Any]]] = (
                game.getPossibleCannonTargets(cannon)
            )

            # No targets
            if len(possibleTargets) == 0:
                continue

            # Sort targets: shoot ships with low life first
            possibleTargets = sorted(
                possibleTargets, key=lambda x: SHIP_HP[x[1]["hull"]] - x[1]["hits"]
            )

            targetRiver: int = possibleTargets[0][0]
            ship: int = possibleTargets[0][1]["id"]

            # Process shot locally, so other cannons will have their targets updated
            game.shootCannon(cannon, targetRiver, ship)

            # Add shot to queue
            socketsQueue.append(sockets[targetRiver - 1])

            payloadsQueue.append(
                {
                    "type": "shot",
                    "auth": gas,
                    "cannon": [cannon[0], cannon[1]],
                    "id": ship,
                }
            )

        # All shots processed locally
        # Fire cannons in parallel (will receive multiple responses per server)
        if len(payloadsQueue) > 0:
            logging.info(f"Firing {len(socketsQueue)} cannons")

            sendMultiShotRequest(socketsQueue, payloadsQueue)

        # Advance game, server might respond with a 'gameover' message
        stateFirstBridge: list[dict[str, Any]] = sendTurnStateRequestFirstBridge(
            sockets, gas, game.turn + 1
        )

        if stateFirstBridge[0]["type"] == "gameover":
            logging.info(stateFirstBridge[0])
            break

        game.advanceTurn(stateFirstBridge)


if __name__ == "__main__":
    # Get args and init log
    parser = initParser()
    args = parser.parse_args()
    game: GameState = GameState()

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=logging.DEBUG,
        filename="client.log",
        filemode="w",
        encoding="utf-8",
    )

    # Connect to all 4 game servers
    sockets: list[socket.socket] = [
        initConnection(args.host, args.port + i) for i in range(NUM_RIVERS)
    ]

    # Step 1: Begin authentication
    res = sendAuthenticationRequest(sockets, args.gas)

    for r in res:
        if r["status"] != 0:
            logging.error(f"Authentication failed with a server. Aborted")
            exit(1)

    # Step 2: Init cannons
    res = sendGetCannonRequest(sockets[0], args.gas)

    game.initCannons(res["cannons"])

    res: list[dict[str, Any]] = sendTurnStateRequestFirstBridge(
        sockets, args.gas, game.turn
    )

    # Step 3: Init turn 0
    game.initFirstBridge(res)

    # Step 4: Run game until game over
    runGame(sockets, args.gas, game)

    # Clean up
    res = sendGameTerminationRequest(sockets[0], args.gas)

    for sock in sockets:
        sock.close()
