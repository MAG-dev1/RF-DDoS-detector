
import socket
import selectors

import types
import types
from collections import deque, defaultdict

import numpy as np
import pandas as pd
sel = selectors.DefaultSelector()

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)
# ...

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Should be ready to read
        if recv_data:
            data.outb += recv_data



        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            try:
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]
            except (BrokenPipeError, ConnectionResetError) as e:
                # Cliente cerró la conexión; limpiar sin traceback ruidoso
                client_ip = data.addr[0] if hasattr(data, 'addr') else '<unknown>'
                print(f"Send error (peer closed) from {client_ip}: {e}")
                try:
                    sel.unregister(sock)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass
            except OSError as e:
                # errores generales del socket: log, limpiar y continuar
                print(f"Send OSError {e} from {data.addr}")
                try:
                    sel.unregister(sock)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass



def start_server():

    #host, port = sys.argv[1], int(sys.argv[2])
    host, port = "localhost", 8080
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((host, port))
    lsock.listen()
    print(f"Listening on {(host, port)}")
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()

if __name__ == '__main__':
    start_server()


