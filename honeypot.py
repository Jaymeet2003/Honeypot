import paramiko
import socket
import threading
import time
import sys

# Dictionary to track login attempts for each username
attempts = {}

# Simulated file system for the honeypot
file_system = {}

# Function to load valid usernames from a file
def load_valid_usernames(file_path="usernames.txt"):
    """
    Reads valid usernames from the specified file.

    Args:
        file_path (str): Path to the file containing valid usernames.

    Returns:
        set: A set of valid usernames.
    """
    try:
        with open(file_path, "r") as f:
            # Read non-empty lines, stripping whitespace
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"[!] Username file '{file_path}' not found. Exiting.")
        sys.exit(1)

# Load valid usernames into a global variable
valid_usernames = load_valid_usernames()

# Class to handle SSH server operations and authentication
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.current_username = None  # Store the username of the current session

    def check_auth_password(self, username, password):
        """
        Handle password authentication.

        Args:
            username (str): Username provided by the client.
            password (str): Password provided by the client.

        Returns:
            paramiko.AUTH_SUCCESSFUL or paramiko.AUTH_FAILED
        """
        global attempts
        self.current_username = username

        # Validate the username against the list of valid usernames
        if username not in valid_usernames:
            print(f"[!] Invalid username: {username}. Terminating connection.")
            return paramiko.AUTH_FAILED

        # Increment the attempt counter for the username
        attempts[username] = attempts.get(username, 0) + 1
        print(f"[+] Login attempt for {username}: Attempt {attempts[username]} with password '{password}'")

        # Grant access if more than 5 attempts have been made
        if attempts[username] > 5:
            print(f"[+] Access granted to {username} after {attempts[username]} attempts.")
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[!] Access denied for {username}.")
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        """Specify allowed authentication methods (password only)."""
        return "password"

    def check_channel_request(self, kind, chanid):
        """
        Handle channel requests from the client.

        Args:
            kind (str): Type of channel request.
            chanid (int): Channel ID.

        Returns:
            paramiko.OPEN_SUCCEEDED or paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        """
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        """
        Handle shell requests from the client.
        
        Args:
            channel: The channel to process.

        Returns:
            bool: True if the request is accepted.
        """
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Accept pseudo-terminal requests from the client."""
        return True

# Function to handle shell commands from the client
def handle_shell(chan, username):
    """
    Manage the shell session for the authenticated user.

    Args:
        chan: The Paramiko channel object.
        username (str): Authenticated username.
    """
    try:
        chan.sendall(f"{username}@honeypot:/$ ".encode())  # Display prompt
        session_active = True
        last_interaction = time.time()  # Track last activity time
        command_buffer = ""  # Buffer for the current command
        command_history = []  # Command history for session
        history_index = -1  # Index for navigating command history

        while session_active:
            # Disconnect session if idle for over 60 seconds
            if time.time() - last_interaction > 60:
                chan.sendall(b"\r\nConnection terminated due to inactivity.\r\n")
                break

            chan.settimeout(1.0)  # Timeout for client input
            try:
                data = chan.recv(1024).decode("utf-8", "ignore")
                if not data:
                    continue

                last_interaction = time.time()  # Reset inactivity timer

                # Process character-by-character input
                for char in data:
                    if char == '\r':  # Enter key
                        chan.sendall(b"\r\n")  # Echo newline
                        command = command_buffer.strip()

                        # Add non-empty commands to history
                        if command:
                            command_history.append(command)
                        history_index = -1  # Reset history navigation
                        command_buffer = ""  # Clear buffer after execution

                        # Process shell commands
                        response = ""
                        if command == "clear":
                            chan.sendall(b"\033c")  # Clear screen using ANSI escape
                        elif command == "ls":
                            files = " ".join(file_system.keys())
                            response = f"{files}\r\n" if files else ""
                        elif command.startswith("echo "):
                            parts = command.split('>')
                            if len(parts) == 2:
                                content = parts[0].strip().split('"')[1]
                                filename = parts[1].strip()
                                if filename.endswith(".txt"):
                                    file_system[filename] = content
                                    response = ""
                                else:
                                    response = "unknown file extension\r\n"
                            else:
                                response = "Invalid command format\r\n"
                        elif command.startswith("cat "):
                            filename = command.split(" ")[1]
                            if not filename.endswith(".txt"):
                                response = "unknown file extension\r\n"
                            elif filename not in file_system:
                                response = f"File {filename} not found\r\n"
                            else:
                                response = f"{file_system[filename]}\r\n"
                        elif command.startswith("cp "):
                            parts = command.split(" ")
                            if len(parts) == 3:
                                source, destination = parts[1], parts[2]
                                if not (source.endswith(".txt") and destination.endswith(".txt")):
                                    response = "unknown file extension\r\n"
                                elif source not in file_system:
                                    response = f"File {source} not found\r\n"
                                else:
                                    file_system[destination] = file_system[source]
                                    response = ""
                            else:
                                response = "Invalid command format\r\n"
                        elif command == "exit":
                            chan.sendall(b"Exiting honeypot. Goodbye!\r\n")
                            session_active = False
                            continue
                        else:
                            response = "Command not found\r\n"

                        # Send response to client
                        chan.sendall(f"{response}{username}@honeypot:/$ ".encode())

                    elif char == '\x7f':  # Backspace key
                        if command_buffer:  # Remove last character if buffer is not empty
                            command_buffer = command_buffer[:-1]
                            chan.sendall(b'\b \b')  # Backspace visually
                    else:  # Append regular character to buffer
                        command_buffer += char
                        chan.sendall(char.encode())  # Echo character back to client

            except socket.timeout:
                continue
            except Exception as e:
                chan.sendall(f"Error: {e}\r\n".encode())
                print(f"Error handling command: {e}")
                session_active = False

    except Exception as main_e:
        print(f"Error during shell session: {main_e}")
    finally:
        print("Closing channel")
        chan.close()

# Function to handle client connections
def handle_connection(client, addr):
    """
    Manage an SSH connection from a client.

    Args:
        client: Client socket object.
        addr: Tuple containing the client IP address and port.
    """
    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey.generate(2048))  # Generate server RSA key
    server = HoneypotServer()

    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        print("[!] SSH negotiation failed.")
        return

    chan = transport.accept(20)  # Wait for a channel
    if chan is None:
        print("[!] No channel.")
        return

    print(f"[+] Channel opened for {addr}")

    # Wait for the client to request a shell
    server.event.wait(10)
    if not server.event.is_set():
        print("[!] Shell request not received.")
        chan.close()
        return

    try:
        username = server.current_username
        if username not in valid_usernames:
            print(f"[!] Invalid username '{username}'. Terminating connection.")
            chan.send(b"Invalid username. Connection closed.\r\n")
            chan.close()
            return

        # Start the shell session
        chan.send(f"Access granted. Welcome {username}.\r\n\r\n".encode())
        handle_shell(chan, username)

    except Exception as e:
        print(f"Error during connection handling: {e}")
    finally:
        if not chan.closed:
            chan.close()
        transport.close()

# Main function to start the SSH honeypot
def main():
    """
    Start the SSH honeypot server.
    """
    if len(sys.argv) != 3 or sys.argv[1] != "-p":
        print("Usage: python honeypot.py -p [port]")
        sys.exit(1)

    port = int(sys.argv[2])  # Parse port number from command-line arguments

    # Set up a listening socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(100)

    print(f"[+] Honeypot listening on port {port}")

    # Accept and handle incoming connections in separate threads
    while True:
        client, addr = server_socket.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_connection, args=(client, addr)).start()

if __name__ == "__main__":
    main()
