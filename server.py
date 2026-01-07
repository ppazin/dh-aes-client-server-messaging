import base64
import json
import socket
import struct
import threading
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


registered_clients = {}
inboxes = {}
lock = threading.Lock()


def handle_client(conn: socket.socket, addr):
    try:
        server_sk = x25519.X25519PrivateKey.generate()
        server_pk = server_sk.public_key().public_bytes_raw()

        send_frame(conn, server_pk)

        client_pk_raw = recv_frame(conn)
        client_pk = x25519.X25519PublicKey.from_public_bytes(client_pk_raw)

        shared = server_sk.exchange(client_pk)
        aes_key = hkdf_derive(shared)

        username = None

        while True:
            frame = recv_frame(conn)
            enc = json.loads(frame.decode("utf-8"))
            msg = aes_decrypt(aes_key, enc)

            cmd = msg.get("cmd")

            if cmd == "REGISTER":
                username = msg.get("username")
                if not username:
                    resp = {"ok": False, "error": "Missing username"}
                else:
                    with lock:
                        registered_clients[username] = True
                        inboxes.setdefault(username, [])
                    resp = {"ok": True, "info": f"Registered as {username}"}

                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

            elif cmd == "SEND":
                if not username:
                    resp = {"ok": False, "error": "Not registered"}
                else:
                    to = msg.get("to")
                    text = msg.get("text", "")

                    with lock:
                        exists = registered_clients.get(to, False)
                        if exists:
                            inboxes.setdefault(to, []).append({
                                "from": username,
                                "ts": int(time.time()),
                                "text": text
                            })
                            resp = {"ok": True}
                        else:
                            resp = {"ok": False, "error": "Recipient does not exist"}

                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

            elif cmd == "FETCH":
                if not username:
                    resp = {"ok": False, "error": "Not registered"}
                else:
                    with lock:
                        msgs = inboxes.get(username, [])
                        inboxes[username] = []
                    resp = {"ok": True, "messages": msgs}

                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

            elif cmd == "QUIT":
                resp = {"ok": True}
                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))
                break

            else:
                resp = {"ok": False, "error": "Unknown command"}
                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except:
            pass


def main():
    host = "0.0.0.0"
    port = 5000

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(50)
    print(f"Server listening on {host}:{port}")

    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
