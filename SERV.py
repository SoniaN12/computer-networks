# setting up a server with basic socket listening that accepts multiple clients and plain text messaging.
# server.py
import socket
import ssl
import json
import threading
import os

HOST = '127.0.0.1'
PORT = 12345



# client_handler.py
import json


def handle_client(conn, addr):
    try:
        while True:
            data = conn.recv(4096).decode('utf-8')  # message authentication
            if not data:
                break
            try:
                message = json.loads(data)
                messag_type = message.get("type")
                if messag_type == "auth":
                    response = handle_auth(message)
                    conn.send(json.dumps(response).encode('utf-8'))
                # allows server to fetch contacts
                if messag_type == "get_contacts":
                    contacts =get_all_users()
                    response  = {"status": "ok", "contacts":contacts}
                    conn.send(json.dumps(response).encode('utf-8'))
                    #add a new contact
                elif messag_type == "add_contact":
                    user = message.get("user")
                    contact = message.get("contact")
                    if add_contact(user,contact):
                        response ={"status":"ok","message":"successfully added contact"}
                    else:
                        response ={"status":"error","message":"failed to add"}
                    conn.send(json.dumps(response).encode('utf-8'))
                # send data command
                if messag_type == "message":
                    print(
                        f"[MESSAGE] FROM{message['from']} to {message['to']}: {message['data']}")  # send message and print response
                    save_message(message['from'], message['to'], message['data'])  # saving the sent message
                    conn.send(json.dumps({"status": "ok"}).encode('utf-8'))
                # when data  sent is  a file instead of a command
                elif messag_type == "file":
                    file_name = message["filename"]
                    file_data = message["data"].encode('utf-8')  # file must be encoded to be sent
                    with open(f"received_{file_name}", 'wb') as f:
                        f.write(file_data)
                    conn.send(json.dumps({"status": "file received"}).encode('utf-8'))

                else:
                    conn.send(json.dumps({"status": "error", "message": "unknown type"}).encode('utf-8'))

            except json.JSONDecodeError:
                conn.send(json.dumps({"status": "error", "message": "Invalid  JSON"}).encode('utf-8'))
            except Exception as e:
                print(f"[ERROR]{e}")

    except Exception as e:
        print(f"[error]{e}")

    finally:
        conn.close()
        print(f"[disconnected] {addr} disconnect.")


def send_to_client(self, client_id, message):
    if client_id in self.clients:
        conn, addr = self.clients[client_id]
        try:
            conn.sendall(json.dumps({"message": message}).encode('utf-8'))
            return True
        except ConnectionError:
            print(f"[SERVER] Failed to send message to {client_id}")
            del self.clients[client_id]
            return False
    else:
        print(f"[SERVER] Client {client_id} not found")
        return False

    # auth.py


import hashlib
import sqlite3
import os


DB_PATH = '../database/chat.db'

def create_database_directory():
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

if not os.path.exists(DB_PATH):
    print(f"[ERROR] Database file does not exist at: {DB_PATH}")
else:
    print(f"[INFO] Database file found at: {DB_PATH}")


def connect_to_database():
    try:
        conn = sqlite3.connect(DB_PATH)
        print("[INFO] Database connection established.")
        return conn
    except sqlite3.Error as e:
        print(f"[ERROR] Unable to open database file: {e}")


def hash_password(password):
    password_bytes = password.encode('utf-8')  # encode password bytes
    hash_object = hashlib.sha256(password_bytes)  # use SHA-256 hash function to create hash object
    password_hash = hash_object.hexdigest().lower()  # hexadecimal representation of hash

    return password_hash


def handle_auth(message):
    mode = message.get("mode")
    username = message.get("username")
    password = message.get("password")

    if not user_name or not password:
        return {"status": "error", "message": "username or password not found"}

    conn = sqlite3.connect(DB_PATH)  # connecting to the database system
    cursor = conn.cursor()

    if mode == "register":
        try:
            cursor.execute("INSERT INTO users(username, password)VALUES(?,?)",
                           (username, hash_password))  # executing a query
            conn.commit()  # commiting the sql query
            return {"status": "ok", "message": "registration successful"}
        except sqlite3.IntegrityError:
            return {"status": "error", "message": "username already exists"}

    elif mode == "login":

        try:

            cursor.execute("select password FROM users where username=?", (username,))
            row = Cursor.fetchone()
            if row and row[0] == hash_password(password):
                return {"status": "ok", "message": "login successful"}

            else:
                return {"status": "error", "message": "invalid input"}
        except Exception as e:

            return {"status": "error", "message": "unknown auth mode"}


# db.py

import sqlite3
import os

def init_db():
    create_database_directory()

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()  # connecting to the database system to execute an sql query
         # creating contacts table
        cursor.execute(''' CREATE TABLE IF NOT EXISTS contacts(
                         user_id INT PRIMARY KEY,
                         username REFERENCES FROM USERS  TEXT NOT NULL,
                         contact FOREIGN KEY 
                         
                         )''')
        # creating users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS  users(
                        username TEXT PRIMARY KEY,
                        password TEXT NOT NULL
                        )''')
         # creating messages table
        cursor.execute('''CREATE TABLE IF NOT EXISTS messages(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender text,
                        receiver text,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')
        conn.commit()
        print(f"[INFO] Database initialized at: {DB_PATH}")
    except sqlite3.Error as e:
        print(f"[ERROR] Database initialization failed: {e}")
    finally:
        conn.close()
def add_contact(username,user_id):
    conn =None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO contacts (username,user_id) VALUES(?,?)',(username,user_id))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"[ERROR Failed to add contact: {e}")
        return  False
    finally:
        if conn:
            conn.close()
if __name__ =="__main__":
   init_db()


def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username FROM users")
        return [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()


def save_message(sender, receiver, message):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages(sender,receiver,message)VALUES(?,?,?)",
                   (sender, receiver, message))
    conn.commit()
    conn.close()


# file_receiver.py
# To handle  incoming file transfers safely
def handle_file_transfer(data, addr):
    file_name = data.get("filename")
    file_data = data.get("data")

    if not file_name or not file_data:
        print(f"invalid file transfer from{addr}")
        return
    safe_file_name = file_name.replace("..", "_safe")
    with open(f"received_{safe_file_name}", "wb") as f:
        f.write(file_data.encode('latin1'))
    print(f"File'{file_name}'received from{addr} and saved as 'received_{safe_file_name}'")

# SSL CONTEXT

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)  # creating a socket object
    server_socket.bind((HOST, PORT))  # bind  the socket to a specific host and port
    server_socket.listen(5)
    print(f"server listening on {HOST}:{PORT}")  # listening for incoming connections
    while True:
        conn, addr = server_socket.accept()  # Accept a new connection
        print(f"[NEW CONNECTION] {addr} connected.")

        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()  # Start the thread


if __name__ == "__main__":
    # Initialize the database
    run_server()  # Start the server



