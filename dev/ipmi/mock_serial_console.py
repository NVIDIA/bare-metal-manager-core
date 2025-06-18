#!/usr/bin/env python3

# Echo data back in a way that impi expects for things like `sol activate`.

import socket
import threading

HOST = "127.0.0.1"
PORT = 9003

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    with conn:
        buffer = b""
        while True:
            data = conn.recv(1024)
            if not data:
                print(f"Connection closed by {addr}")
                break
            print(f"Received from {addr}: {data!r}")

            conn.sendall(data)

            buffer += data
            if buffer.endswith(b"\n") or buffer.endswith(b"\r"):
                buffer = b""
                # Emulate an `ed` session (https://www.gnu.org/fun/jokes/ed-msg.html) :-D
                conn.sendall(b"\r\n?\r\n")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on port {PORT}...")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit
