
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind(("127.0.0.1", 5000))
server.listen(5)

print("TCP Server is waiting for connections...")

while True:
    conn, addr = server.accept()
    print("Connected by:", addr)

    data = conn.recv(1024).decode()
    print("Message received:", data)

    conn.sendall("Message received successfully".encode())
    conn.close()
