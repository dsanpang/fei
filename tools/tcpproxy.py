# -*- coding: utf-8 -*-
"""One-shot TCP capture proxy: listen :4434, forward to 127.0.0.1:4433,
dump both directions to /tmp/cap_c2s.bin and /tmp/cap_s2c.bin."""
import socket
import threading
import time

LISTEN = ("127.0.0.1", 4434)
TARGET = ("127.0.0.1", 4433)
c2s = open(r"C:\fei_probe\cap_c2s.bin", "wb")
s2c = open(r"C:\fei_probe\cap_s2c.bin", "wb")
lock = threading.Lock()


def pump(src, dst, f):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            with lock:
                f.write(data)
                f.flush()
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    lst = socket.socket()
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(LISTEN)
    lst.listen(1)
    print("proxy listening on %s" % (LISTEN,))
    while True:
        client, _ = lst.accept()
        server = socket.socket()
        server.connect(TARGET)
        t1 = threading.Thread(target=pump, args=(client, server, c2s))
        t2 = threading.Thread(target=pump, args=(server, client, s2c))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print("connection closed", time.strftime("%H:%M:%S"))


if __name__ == "__main__":
    main()
