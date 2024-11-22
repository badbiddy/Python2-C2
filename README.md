# Python2 C2 & Implant

A lightweight command-and-control (C2) server and implant system designed for secure task execution and result collection. This project provides encryption for communication, supports direct server connections (without a proxy), and saves task results in a readable format.

## Features
- Secure Communication: Uses XOR encryption combined with HMAC for data integrity.
- Lightweight Design: Written in Python 2 for legacy compatibility.
- Direct and Proxy Support: The implant can connect directly or through a proxy.
- Readable Output: Task results are stored in a plain-text format for easy review.
- Task Management: Tasks are queued via a tasks.txt file and results are saved in results.txt.

## Contents
- c2.py: The C2 server script.
- implant.py: The implant script that connects to the C2 server.
- tasks.txt: Input file for tasks (on the server side).
- results.txt: Output file for task results (on the server side).

## Requirements
- Python 2 installed on both the server and client machines.

## Server Setup
- Place c2.py, tasks.txt, and results.txt in the same directory.
- Ensure tasks.txt is formatted as one task per line in JSON format:

`{"task_id": "001", "command": "id"}`
`{"task_id": "002", "command": "ifconfig"}`

- Start the server:

`python2 c2.py`

## Implant Setup
- Place implant.py on the client machine.
- Edit the file to set the C2_HOST variable to the IP address of your server:

`C2_HOST = '<C2_SERVER_IP>'`

- Run the implant:

`python2 implant.py`

## How It Works

### C2 Server

- The server reads tasks from tasks.txt and sends them to the implant.
- Results from the implant are stored in results.txt in a clean, readable format.

### Implant

- The implant fetches tasks from the server, executes them, and sends the results back.
- If no tasks are available, the implant waits and retries periodically.

## Security Considerations
- This implementation uses XOR-based encryption with HMAC for communication security. While sufficient for basic obfuscation, it is not a substitute for modern encryption standards like AES.
- Always use a secure and private environment for testing and execution.

## Limitations
- Designed for Python 2, which is deprecated. For production use, consider migrating to Python 3.
- This is a proof-of-concept system and is not intended for production environments.

## License
- This project is provided "as-is" for educational purposes. Use it responsibly and at your own risk.
