import base64
import json
import socket
import struct
import threading
import time
import os

import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv


load_dotenv() 


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


db_pool = None


def init_db_pool():
    """Initialize the database connection pool"""
    global db_pool
    
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "postgres")
    db_user = os.getenv("DB_USER", "postgres")
    db_password = os.getenv("DB_PASSWORD", "")
    
    db_pool = ThreadedConnectionPool(
        minconn=1,
        maxconn=20,
        host=db_host,
        port=db_port,
        database=db_name,
        user=db_user,
        password=db_password
    )
    print(f"Database pool initialized: {db_user}@{db_host}:{db_port}/{db_name}")


def get_db_connection():
    """Get a database connection from the pool"""
    return db_pool.getconn()


def return_db_connection(conn):
    """Return a database connection to the pool"""
    db_pool.putconn(conn)


def register_user(username: str) -> tuple[bool, str, int]:
    """
    Register a user in the database
    Returns: (success, message, user_id)
    """
    db_conn = get_db_connection()
    try:
        with db_conn.cursor() as cur:
            cur.execute(
                "SELECT user_id FROM dh_aes_mess.users WHERE username = %s",
                (username,)
            )
            existing = cur.fetchone()
            
            if existing:
                cur.execute(
                    "UPDATE dh_aes_mess.users SET last_seen_at = now() WHERE username = %s RETURNING user_id",
                    (username,)
                )
                user_id = cur.fetchone()[0]
                db_conn.commit()
                return True, f"Logged in as {username}", user_id
            else:
                cur.execute(
                    "INSERT INTO dh_aes_mess.users (username, last_seen_at) VALUES (%s, now()) RETURNING user_id",
                    (username,)
                )
                user_id = cur.fetchone()[0]
                db_conn.commit()
                return True, f"Registered as {username}", user_id
    except Exception as e:
        db_conn.rollback()
        return False, f"Database error: {str(e)}", None
    finally:
        return_db_connection(db_conn)


def send_message(sender_user_id: int, recipient_username: str, text: str) -> tuple[bool, str]:
    """
    Send a message from one user to another
    Returns: (success, message)
    """
    db_conn = get_db_connection()
    try:
        with db_conn.cursor() as cur:
            cur.execute(
                "SELECT user_id FROM dh_aes_mess.users WHERE username = %s",
                (recipient_username,)
            )
            recipient = cur.fetchone()
            
            if not recipient:
                return False, "Recipient does not exist"
            
            recipient_user_id = recipient[0]
            
            cur.execute(
                """
                INSERT INTO dh_aes_mess.messages 
                (sender_user_id, recipient_user_id, body, status)
                VALUES (%s, %s, %s, 'unread')
                """,
                (sender_user_id, recipient_user_id, text)
            )
            db_conn.commit()
            return True, "Message sent"
    except Exception as e:
        db_conn.rollback()
        return False, f"Database error: {str(e)}"
    finally:
        return_db_connection(db_conn)


def fetch_messages(user_id: int) -> tuple[bool, str, list]:
    """
    Fetch all unread messages for a user and mark them as read
    Returns: (success, message, list_of_messages)
    """
    db_conn = get_db_connection()
    try:
        with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT m.message_id, u.username as from_user, 
                       EXTRACT(EPOCH FROM m.sent_at)::integer as ts, 
                       m.body as text
                FROM dh_aes_mess.messages m
                JOIN dh_aes_mess.users u ON m.sender_user_id = u.user_id
                WHERE m.recipient_user_id = %s AND m.status = 'unread'
                ORDER BY m.sent_at ASC
                """,
                (user_id,)
            )
            messages = cur.fetchall()
            
            if messages:
                message_ids = [m['message_id'] for m in messages]
                cur.execute(
                    """
                    UPDATE dh_aes_mess.messages 
                    SET status = 'read' 
                    WHERE message_id = ANY(%s)
                    """,
                    (message_ids,)
                )
            
            db_conn.commit()
            
            formatted_messages = [
                {
                    "from": m["from_user"],
                    "ts": m["ts"],
                    "text": m["text"]
                }
                for m in messages
            ]
            
            return True, "Messages fetched", formatted_messages
    except Exception as e:
        db_conn.rollback()
        return False, f"Database error: {str(e)}", []
    finally:
        return_db_connection(db_conn)


def handle_client(conn: socket.socket, addr):
    try:
        server_sk = x25519.X25519PrivateKey.generate()
        server_pk = server_sk.public_key().public_bytes_raw()

        send_frame(conn, server_pk)

        client_pk_raw = recv_frame(conn)
        client_pk = x25519.X25519PublicKey.from_public_bytes(client_pk_raw)

        shared = server_sk.exchange(client_pk)
        aes_key = hkdf_derive(shared)

        user_id = None
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
                    success, info, uid = register_user(username)
                    if success:
                        user_id = uid
                        resp = {"ok": True, "info": info}
                    else:
                        resp = {"ok": False, "error": info}

                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

            elif cmd == "SEND":
                if not user_id:
                    resp = {"ok": False, "error": "Not registered"}
                else:
                    to = msg.get("to")
                    text = msg.get("text", "")
                    
                    success, info = send_message(user_id, to, text)
                    if success:
                        resp = {"ok": True}
                    else:
                        resp = {"ok": False, "error": info}

                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

            elif cmd == "FETCH":
                if not user_id:
                    resp = {"ok": False, "error": "Not registered"}
                else:
                    success, info, messages = fetch_messages(user_id)
                    if success:
                        resp = {"ok": True, "messages": messages}
                    else:
                        resp = {"ok": False, "error": info}

                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

            elif cmd == "QUIT":
                resp = {"ok": True}
                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))
                break

            else:
                resp = {"ok": False, "error": "Unknown command"}
                send_frame(conn, json.dumps(aes_encrypt(aes_key, resp)).encode("utf-8"))

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        try:
            conn.close()
        except:
            pass


def main():
    init_db_pool()
    
    host = "0.0.0.0"
    port = 5000

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(50)
    print(f"Server listening on {host}:{port}")

    while True:
        conn, addr = s.accept()
        print(f"New connection from {addr}")
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()