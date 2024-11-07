import threading
from authority import run_server 
from common import ports

# Spawn 10 servers, each on a separate port and thread
threads = []

for port in ports:
    thread = threading.Thread(target=run_server, args=(port,))
    threads.append(thread)
    thread.start()

# Optional: Wait for all threads to complete (they won't in this case since servers run forever)
for thread in threads:
    thread.join()
