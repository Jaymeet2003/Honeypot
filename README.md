
# SSH Honeypot

An **SSH Honeypot** designed to simulate an SSH server, allowing you to monitor unauthorized login attempts and study attacker behavior in a controlled environment. It tracks login attempts and logs commands executed by users for security analysis and research purposes.

---

## Features

- **Simulated SSH Server**: Responds to SSH connections and provides a minimal shell environment.
- **Authentication Tracking**: Logs all login attempts, granting access after multiple failed attempts (default: 5).
- **File System Simulation**:
  - Supports basic shell commands like `ls`, `cat`, `cp`, `echo`, and `clear`.
  - Allows file creation, reading, and manipulation.
- **Idle Timeout**: Automatically disconnects inactive sessions after 60 seconds.
- **Multi-Threaded**: Supports handling multiple simultaneous connections.

---

## Prerequisites

1. **Python 3.x**: Ensure Python 3 is installed.
2. **Dependencies**:
   - Install required libraries using:
     ```bash
     pip install paramiko
     ```

---

## Getting Started

### Command-Line Usage

Run the honeypot with the following syntax:

```bash
python honeypot.py -p [port]
```

Replace `[port]` with the port you want the honeypot to listen on.

### Example

```bash
python honeypot.py -p 2222
```

### Username File

Create a file named `usernames.txt` in the same directory. This file should contain the list of valid usernames, one per line.

Example `usernames.txt`:
```
admin
root
testuser
```

---

## Simulated Shell Commands

The honeypot provides a minimal shell for connected users. Supported commands:

| Command                       | Description                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------|
| `ls`                          | Lists all files in the simulated file system.                                                    |
| `echo "text" > filename.txt`  | Writes "text" into a file named `filename.txt`.                                                   |
| `cat filename.txt`            | Displays the contents of `filename.txt`. Returns an error if the file does not exist or is invalid.|
| `cp source.txt destination.txt` | Copies the content of `source.txt` to `destination.txt`. Both files must have `.txt` extensions.  |
| `clear`                       | Clears the terminal screen.                                                                      |
| `exit`                        | Exits the shell and terminates the session.                                                      |

---

## Logs and Output

The honeypot logs all activity to the console, including:
- Connection attempts (IP, port).
- Login attempts (username, password, attempt count).
- Commands executed by users during sessions.

Sample log output:
```
[+] Honeypot listening on port 2222
[+] Connection from 192.168.1.10:54321
[+] Login attempt for admin: Attempt 1 with password '12345'
[!] Access denied for admin.
[+] Login attempt for admin: Attempt 6 with password 'password123'
[+] Access granted to admin after 6 attempts.
[+] Channel opened for ('192.168.1.10', 54321)
```

---

## Security Disclaimer

This SSH honeypot is intended for **educational and research purposes only**. Use it responsibly and ensure compliance with your local laws and regulations. Unauthorized use against third-party systems is strictly prohibited.

---

## Future Enhancements

- Add persistent logging to files.
- Make login attempt thresholds configurable.
- Add external alerting or integration with monitoring systems.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author
Jimmy Patel
Created as an educational project for learning and security research.

---

**Happy Honeypotting! 🐝**
