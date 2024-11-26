import paramiko
import socket
import threading
import time
import sys

# Dictionary to keep track of login attempts
attempts = {}

# Fake file system
file_system = {}

# Class to handle SSH server operations and authentication
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        global attempts
        # Increment attempt count
        attempts[username] = attempts.get(username, 0) + 1
        print(f"[+] Login attempt for {username}: Attempt {attempts[username]} with password '{password}'")

        if attempts[username] > 5:
            print(f"[+] Access granted to {username} after {attempts[username]} attempts.")
            # Grant access and stop further prompts
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[!] Access denied for {username}.")
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True




# Function to handle the shell session
def handle_shell(chan, username):
    try:
        chan.sendall(f"{username}@honeypot:/$ ".encode())
        session_active = True
        last_interaction = time.time()
        command_buffer = ""
        command_history = []  # Command history to support arrow keys
        history_index = -1  # Current position in the history

        while session_active:
            # Check for idle timeout
            if time.time() - last_interaction > 60:
                chan.sendall(b"\r\nConnection terminated due to inactivity.\r\n")
                break

            chan.settimeout(1.0)
            try:
                data = chan.recv(1024).decode("utf-8", "ignore")
                if not data:
                    continue

                last_interaction = time.time()

                # Process received data character by character
                for char in data:
                    if char == '\r':  # Enter key
                        chan.sendall(b"\r\n")  # Echo newline
                        command = command_buffer.strip()

                        if command:  # Add non-empty commands to history
                            command_history.append(command)
                        history_index = -1  # Reset history navigation
                        command_buffer = ""  # Clear the buffer after processing

                        # Initialize a default response
                        response = ""

                        # Command handling logic
                        if command == "clear":
                            chan.sendall(b"\033c")  # ANSI escape to clear screen
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

                        # Send the response (if any)
                        chan.sendall(f"{response}{username}@honeypot:/$ ".encode())


                    elif char == '\x7f':  # Backspace key
                        if command_buffer:  # Only backspace if there's content in the buffer
                            command_buffer = command_buffer[:-1]
                            # Send backspace to erase character visually
                            chan.sendall(b'\b \b')

                    else:  # Regular character
                        command_buffer += char
                        chan.sendall(char.encode())  # Echo the character back to the client

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


def handle_connection(client, addr):
    global attempts

    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey.generate(2048))
    server = HoneypotServer()

    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        print("[!] SSH negotiation failed.")
        return

    chan = transport.accept(20)
    if chan is None:
        print("[!] No channel.")
        return

    print(f"[+] Channel opened for {addr}")

    # Wait for the shell request from the client
    server.event.wait(10)
    if not server.event.is_set():
        print("[!] Shell request not received.")
        chan.close()
        return

    try:
        # Immediately get the username and proceed if authentication is successful
        username = transport.get_username()
        if attempts.get(username, 0) > 5:
            print(f"[+] Access granted to {username} after {attempts[username]} attempts.")
            chan.send("\r\nAccess granted. Welcome to the honeypot.\r\n".encode())
            handle_shell(chan, username)
            return

        # Handle password attempts
        password_buffer = ""
        while True:
            try:
                chan.settimeout(5.0)
                data = chan.recv(1024).decode()
                if not data:
                    print("[!] No input received; closing channel.")
                    return  # Exit if no input is received (client disconnected)

                password_buffer += data

                # Check if the buffer ends with "\r" (Enter key)
                if password_buffer.endswith("\r"):
                    input_password = password_buffer.strip()
                    print(f"[+] Received password attempt from {username}: {input_password}")
                    attempts[username] += 1  # Increment attempts for each complete password entry
                    password_buffer = ""  # Clear the buffer after processing

                    # Check if the maximum number of attempts has been reached
                    if attempts[username] > 5:
                        chan.send("\r\nAccess granted. Welcome to the honeypot.\r\n".encode())
                        print(f"[+] Access granted to {username} after brute-force attempts.")
                        handle_shell(chan, username)
                        return  # Exit after a successful shell session

                    # Send "Access denied" message
                    chan.send("\r\nAccess denied. Try again.".encode())
                    print(f"[!] Access denied to {username}. Waiting for retry...")

                    # Wait for client to press Enter (\r) for the next attempt prompt
                    chan.send("\r\nReenter Password:".encode())

            except socket.timeout:
                print("[!] Client interaction timed out.")
                return  # Exit the loop if the client times out

    except Exception as e:
        print(f"Error during connection handling: {e}")
    finally:
        if not chan.closed:
            print("[!] Closing channel after retries.")
            chan.close()
        transport.close()


# Main function to start the SSH honeypot
def main():
    if len(sys.argv) != 3 or sys.argv[1] != "-p":
        print("Usage: python honeypot.py -p [port]")
        sys.exit(1)

    port = int(sys.argv[2])
    host_key = paramiko.RSAKey.generate(2048)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(100)

    print(f"[+] Honeypot listening on port {port}")

    while True:
        client, addr = server_socket.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_connection, args=(client, addr)).start()

if __name__ == "__main__":
    main()
