import socket
import time, threading

def server():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_socket.bind(('localhost', 8888))

    # Listen for incoming connections
    server_socket.listen(1)

    print("Server is listening...")

    # Accept a connection
    connection, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    # Receive data from the client
    data = connection.recv(1024)
    print(f"Received: {data.decode()}")

    # Close the connection gracefully
    connection.close()
    print("Connection closed")

def client():
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server
    client_socket.connect(('localhost', 8888))

    # Send data to the server
    message = "Hello, server!"
    client_socket.sendall(message.encode())
    print(f"Sent: {message}")

    # Close the connection gracefully
    client_socket.close()
    print("Connection closed")

if __name__ == "__main__":
    # Start the server in a separate thread
    server_thread = threading.Thread(target=server)
    server_thread.start()

    # Wait for a short time for the server to start
    time.sleep(1)

    # Start the client
    client()

