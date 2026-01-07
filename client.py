import base64
import json
import socket
import struct
import time

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def recv_frame(conn):
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    return recv_exact(conn, length)


def send_frame(conn, payload: bytes):
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def hkdf_derive(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dh-aes-chat-v1",
    ).derive(shared_secret)


def aes_encrypt(aes_key: bytes, obj: dict) -> dict:
    aesgcm = AESGCM(aes_key)
    nonce = __import__("os").urandom(12)
    pt = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    ct = aesgcm.encrypt(nonce, pt, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


def aes_decrypt(aes_key: bytes, enc: dict) -> dict:
    aesgcm = AESGCM(aes_key)
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ct"])
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))


def rpc(conn, aes_key, obj):
    send_frame(conn, json.dumps(aes_encrypt(aes_key, obj)).encode("utf-8"))
    resp_enc = json.loads(recv_frame(conn).decode("utf-8"))
    return aes_decrypt(aes_key, resp_enc)


def main():
    host = "127.0.0.1"
    port = 5000

    username = input("Username: ").strip()

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))

    server_pk_raw = recv_frame(conn)
    server_pk = x25519.X25519PublicKey.from_public_bytes(server_pk_raw)

    client_sk = x25519.X25519PrivateKey.generate()
    client_pk_raw = client_sk.public_key().public_bytes_raw()

    send_frame(conn, client_pk_raw)

    shared = client_sk.exchange(server_pk)
    aes_key = hkdf_derive(shared)

    r = rpc(conn, aes_key, {"cmd": "REGISTER", "username": username})
    if not r.get("ok"):
        print("REGISTER failed:", r.get("error"))
        return

    print("Commands:")
    print("  /send <user> <message>")
    print("  /fetch")
    print("  /quit")

    while True:
        line = input("> ").strip()
        if not line:
            continue

        if line.startswith("/send "):
            parts = line.split(" ", 2)
            if len(parts) < 3:
                print("Usage: /send <user> <message>")
                continue

            to = parts[1].strip()
            text = parts[2]

            r = rpc(conn, aes_key, {"cmd": "SEND", "to": to, "text": text})
            if r.get("ok"):
                print("OK")
            else:
                print("ERR:", r.get("error"))

        elif line == "/fetch":
            r = rpc(conn, aes_key, {"cmd": "FETCH"})
            if not r.get("ok"):
                print("ERR:", r.get("error"))
                continue

            msgs = r.get("messages", [])
            if not msgs:
                print("(no messages)")
                continue

            for m in msgs:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m["ts"]))
                print(f"[{ts}] {m['from']}: {m['text']}")

        elif line == "/quit":
            rpc(conn, aes_key, {"cmd": "QUIT"})
            break

        else:
            print("Unknown command")

    conn.close()


if __name__ == "__main__":
    main()
