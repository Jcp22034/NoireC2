import socket
import threading

class Message:
    def __init__(self, action, data):
        self.action = action
        self.data = data

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)

    print(f"TCP server running on port {port}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            print(f"Connection from {address}")

            # Start a new thread to handle communication with the connected client
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()

    except KeyboardInterrupt:
        print("Server stopped by user.")
        server_socket.close()
        
def handle_client(client_socket):
    # Function to handle communication with a connected client
    try:
        # Send a request to the connected client
        request_message = Message(action="request", data="Hello from the server!")
        client_socket.send(str(request_message.__dict__).encode())

        # Receive and process the response from the client
        response_data = client_socket.recv(1024).decode()
        response_message = Message(**eval(response_data))
        print(f"Received response from client: {response_message.data}")

    except Exception as e:
        print(f"Error handling client: {e}")

    finally:
        client_socket.close()

start_server(9595)

def start_server(port:int):
    print(f'C2 server started on port: {str(port)}')