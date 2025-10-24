import socket
import threading
import time
import random

HOST = '127.0.0.1'
PORT = 8080
CANT_CLIENTS = 500 #simulamos la cantidad de clientes.
BASE_PORT = 50000
SLEEP_TIME=0.5
def lanzar(client_id):
   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #local_port = BASE_PORT + client_id
        #s.bind(('0.0.0.0', local_port))
        s.connect((HOST, PORT))
        
        sendData = random.randbytes(1024)

        start = time.time()
        s.sendall(sendData)
        #f'Ping TCP {client_id}'.encode()
        data = s.recv(1024)
        packet_size = len(data)
        end = time.time()
        print(f"Cliente {client_id} RTT: {end - start} ms")



threads = []
for i in range(CANT_CLIENTS):
    t = threading.Thread(target=lanzar, args=(i,))
  
    threads.append(t)
    t.start()
    time.sleep(SLEEP_TIME)

for t in threads:
    t.join()
