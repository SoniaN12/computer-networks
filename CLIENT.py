import socket
import ssl
import json
import threading

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345


# creating interface for sending files and messaging with use of server socket
def receive_messages(sock):
    while True:
        try:
            data = sock.recv(4096).decode('utf-8')
            if data:
                print(f"[SERVER]{data}")
            else:
                break  # connection closed

        except Exception as e:
            print(f"[ERROR]Receiving message:{e}")

            break
import json

def get_contacts(sock):
    """
    Request the contact list from the server and print it.
    `sock` is the connected socket object.
    """
    # Send request message
    request = json.dumps({"type": "get_contacts"})
    sock.send(request.encode('utf-8'))

    # Receive response
    response = sock.recv(4096).decode('utf-8')
    data = json.loads(response)

    if data.get("status") == "ok" and "contacts" in data:
        contacts = data["contacts"]
        print("Your contacts:")
        for contact in contacts:
            print(f" - {contact}")
    else:
        print("Failed to fetch contacts or no contacts available.")

def client_server():
    # context = ssl.create_default_context() # Assuming SSL is needed
    # context.check_hostname = False
    # context.verify_mode = ssl.CERT_NONE

    sock = None
    conn = None

    try:
        # sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
        # If using SSL:
        # conn = context.wrap_socket(sock, server_hostname=SERVER_HOST)
        # If not using SSL:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        conn = sock

        threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()

        while True:
            command = input("Enter command (auth/message/file/contacts/quit): ").strip()
            if command == "auth":
                mode = input("Mode(register/login):")
                username = input("input username:")
                password = input("input password:")
                payload = json.dumps({"type": "auth", "mode": mode, "username": username, "password": password})
                print(f"[CLIENT]sending auth payload:{payload}")
                conn.send(payload.encode('utf-8'))

            elif command == "message":
                sender = input("from:")
                receiver = input("to:")
                msg = input("message:")
                payload = json.dumps({"type": "message", "from": sender, "to": receiver, "data": msg})
                print(f"[CLIENT]sending message payload : {payload}")

                conn.send(payload.encode('utf-8'))

            elif command == "ping":
                conn.send(json.dumps({"type": "ping"}).encode('utf-8'))

            elif command == "file":
                print("File sending not done.")  # Assuming send_file is defined elsewhere

            elif command == "contacts":
                get_contacts(conn)  # Assuming get_contacts is defined elsewhere

            elif command == "quit":
                print("Exit chat.")
                break
    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused. Make sure the server is running on {SERVER_HOST}:{SERVER_PORT}")
    except Exception as e:
        print(f"[ERROR] Client error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    client_server()

# You will need to run the server (defined in the previous cell) before running this client function.
# client_server() # Call this function to start the client interaction


# Placeholder functions (replace with your actual implementations)
