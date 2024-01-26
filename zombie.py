import subprocess
import psutil
from multiprocessing import Process

def set_kernel_params():
    commands = [
        ["sudo", "sysctl", "-w", "net.ipv4.tcp_keepalive_intvl=3"],
        ["sudo", "sysctl", "-w", "net.ipv4.tcp_keepalive_probes=100"],
        ["sudo", "sysctl", "-w", "net.ipv4.tcp_keepalive_time=60"]
    ]

    for command in commands:
        subprocess.call(command)

def show_all_tcp_session():
    for con in psutil.net_connections(kind="tcp"):
        print(f"fd  : {con.fd} family: {con.family} type: {con.type}  l_addr : {con.laddr} r_addr : {con.raddr} status : {con.status} pid: {con.pid}")

def capture_tcp_session(port, output_file):    
    subprocess.call(["sudo", "tcpdump", "-c", "1", "-i", "wlo1", "port", str(port), "-n", "-w", output_file])
    
def using_tcp_dump_parallel():
    processes = []
    
    for con in psutil.net_connections(kind="tcp"):
        port = con.laddr[1]
        output_file = f"output/out_{port}.pcap" 
        process = Process(target=capture_tcp_session, args=(port, output_file))
        processes.append(process)
        process.start()
    for process in processes:
        process.join()

if __name__ == "__main__":
    #set_kernel_params()  
    #show_all_tcp_session()  
    using_tcp_dump_parallel()