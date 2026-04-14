# ---------- IMPORTS ----------
from classes.SSH import SSH, handle_shell
import paramiko, socket , threading, os
# ----------- NEEDED ----------
KEY_FILE = "server.key"
if os.path.exists(KEY_FILE):
    HOST_KEY = paramiko.RSAKey(filename=KEY_FILE)
    print(f"loaded host key from {KEY_FILE}")
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_FILE)
    print(f"generated and saved new host key to {KEY_FILE}")

# ---------- Func -------------
def Handle_Client(client_socket,addresss):
    print(f"[+] Connection From {addresss}")
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    ip = addresss[0]
    server = SSH(ip)
    transport.start_server(server=server)

    channel = transport.accept(timeout=20)
    if channel is None:
        print("[-] No channel opened.")
        return
    print("Channel C0nnected")
    handle_shell(channel, ip)
    

def start_server(host="0.0.0.0", port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[*] Listening on {host}:{port}")

    while True:
        client, addr = sock.accept()
        thread = threading.Thread(target=Handle_Client, args=(client, addr))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_server()