import socket
import threading
from queue import Queue

target = "127.0.0.1"
queue = Queue()
open_ports = []

def scan_ports(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) # Set a timeout for the connection attempt

    result = s.connect_ex((target, port))
    s.close()

    return result == 0

def fill_queue(port_list):
    for port in port_list:
        queue.put(port)

def worker():
    while not queue.empty():
        port = queue.get()

        if scan_ports(port):
            print(f"Port {port} is open")
            open_ports.append(port)

        queue.task_done()

port_list = range(1, 1024)
fill_queue(port_list)

thread_list = []

for t in range(100):
    thread = threading.Thread(target=worker)
    thread_list.append(thread)

for thread in thread_list:
    thread.start()

for thread in thread_list:
    thread.join()  # Wait for all threads to finish

print("Open ports are:", open_ports)