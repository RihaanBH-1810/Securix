import psutil
from scapy.all import sr, IP, TCP, IPv6
from multiprocessing import Process, Queue

not_interested = ["LISTEN", "NONE", "SYN_SENT"]
connections_list = []
working = []
zombie = []

def probe_the_port(ip, port, ip6=False, result_queue=None, zombie_queue=None):
    if ip6:
        packet = IPv6(dst=ip) / TCP(dport=port, flags="S")
        ans, _ = sr(packet, timeout=5,)
    else:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        ans, _ = sr(packet, timeout=5)
    if ans:
        result_queue.put((ip, ans[0][1].sprintf('%TCP.flags%')))
    else:
        zombie_queue.put((ip, port))    

result_queue = Queue()
zombie_queue = Queue()

for con in psutil.net_connections():
    if con.status not in not_interested:
        connections_list.append(con)

processes = []
if connections_list:
    for con in connections_list:
        print(con.raddr)
    for connection in connections_list:
        if str(connection.family) == "AddressFamily.AF_INET6":
            process = Process(target=probe_the_port, args=(connection.raddr[0], connection.raddr[1], True, result_queue, zombie_queue))
            processes.append(process)
            process.start()
        elif str(connection.family) == "AddressFamily.AF_INET":
            process = Process(target=probe_the_port, args=(connection.raddr[0], connection.raddr[1], False, result_queue, zombie_queue))
            processes.append(process)
            process.start()

for process in processes:
    process.join()

while not result_queue.empty():
    result = result_queue.get()
    working.append(result)

while not zombie_queue.empty():
    zombie_result = zombie_queue.get()
    zombie.append(zombie_result)

print("Working:")
for work in working:
    print(work)

print("Zombie:")
for zombie_result in zombie:
    print(zombie_result)
