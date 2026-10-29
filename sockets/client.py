
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect(("127.0.0.1", 5000))

message = input("Enter a message: ")
client.sendall(message.encode())

response = client.recv(1024).decode()
print("Server response:", response)

client.close()
