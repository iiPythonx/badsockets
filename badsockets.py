# Copyright 2022 iiPython
# Resources used:
#   - https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
#   - https://www.pycryptodome.org/src/examples#encrypt-data-with-aes
#   - https://gist.github.com/aellerton/2988ff93c7d84f3dbf5b9b5a09f38ceb

# Modules
import struct
import socket
from typing import Tuple
from threading import Thread
from types import FunctionType
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Class structures
class BadSocketConnection(object):
    def __init__(self, sock: socket.socket, keys: dict, side: int) -> None:
        self.sock, self.keys, self.side, self.addr = sock, keys, side, sock.getpeername()
        [setattr(self, a, getattr(self.sock, a)) for a in dir(self.sock) if not (a[:2] == "__" or hasattr(self, a))]
        self.handshake()

    def handshake(self) -> None:
        if self.side == 0:  # We are the server
            self.session_key = get_random_bytes(16)
            self.peer_public = RSA.import_key(self.sock.recv(len(self.keys["pub"].export_key("DER"))))
            return self.sock.sendall(PKCS1_OAEP.new(self.peer_public).encrypt(self.session_key))

        # Client-side logic
        self.sock.sendall(self.keys["pub"].export_key("DER"))
        self.session_key = PKCS1_OAEP.new(self.keys["priv"]).decrypt(self.sock.recv(self.keys["priv"].size_in_bytes()))

    def send(self, data: bytes) -> None:
        aes = AES.new(self.session_key, AES.MODE_EAX)
        msg = b"".join([aes.nonce, aes.encrypt(data)])
        try:
            return self.sock.sendall(struct.pack(">I", len(msg)) + msg)

        except (BrokenPipeError, TimeoutError):  # TODO: add other exceptions here for more protection
            if self.side == 0:
                return

            self.reconstruct()
            self.send(data)

    def recv(self) -> bytes:
        raw_msglen = self.sock.recv(4)
        if not raw_msglen:
            return None

        nonce = self.sock.recv(16)
        ciphertext = self.sock.recv(struct.unpack(">I", raw_msglen)[0] - 16)
        return AES.new(self.session_key, AES.MODE_EAX, nonce).decrypt(ciphertext)

    def reconstruct(self) -> None:
        bs = BadSocket()
        bs.connect_ex(self.addr)
        self.sock = bs.sock
        self.handshake()

class BadSocket(object):
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen = self.sock.listen

        # Keypair generation (side-independent)
        keypair = RSA.generate(2048)
        self.keys = {"pub": keypair.publickey(), "priv": keypair}
        del keypair

    def bind(self, *args) -> None:
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return self.sock.bind(*args)

    def accept(self) -> None:
        client, addr = self.sock.accept()
        return BadSocketConnection(client, self.keys, 0), addr

    def connect(self, *args) -> None:
        self.sock.connect(*args)
        return BadSocketConnection(self.sock, self.keys, 1)

    def connect_ex(self, *args) -> None:
        self.sock.connect(*args)

class AutoProcessor(object):
    def __init__(
        self,
        address: Tuple[str, int],
        backlog: int = 5,
        callback: FunctionType = None
    ) -> None:
        if callback is None:
            raise ValueError("Callback function cannot be None!")

        self.callback = callback

        # Initialize BadSocket
        self.bs = BadSocket()
        self.bs.bind(address)
        self.bs.listen(backlog)

    def handle(self, conn: BadSocketConnection, addr: Tuple[str, int]) -> None:
        try:
            self.callback(conn, addr)

        except Exception as e:
            print(f"BadSockets: {e}")

        conn.close()

    def go(self) -> None:
        while self.bs:
            conn, addr = self.bs.accept()
            conn.settimeout(10)
            Thread(target = self.handle, args = [conn, addr]).start()
