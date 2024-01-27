import psutil
import threading
import subprocess
import functools


p_z = []
timers = []
kill_list = []


def check_established_cases():
    pass


def eliminate_without_pid():
    pass


def check_probable_zombies():
    p_z.clear()
    for c in psutil.net_connections(kind="tcp"):
        if c.status in ["FIN_WAIT2", "FIN_WAIT1", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT" ]:
            p_z.append(c)
            print("done")
        elif c.status == "ESTABLISHED":
            check_established_cases()

    if not p_z:
        print("None")


def set_timer():
    timers.clear()

    for p in p_z:
        timers.append(threading.Timer(5.0, functools.partial(z_kill, p)))



def execute():
    for timer in timers:
        timer.start()


def z_kill(zombie):
    if zombie.status in ["FIN_WAIT2", "FIN_WAIT1", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT"]:
        kill_list.append(zombie)
        print(kill_list)


def kill(kill_list):
    for con in kill_list:
        if con.pid == None :
                subprocess.call(["ss", "-k", "dst", con.laddr[0], "dport","=", con.laddr[1]])
        elif con.pid != None:
                pid = str(con.pid)
                subprocess.call(["sudo", "kill", "-9", pid])


def set_kernel_params():
    commands = [
        ["sudo", "sysctl", "-w", "net.ipv4.tcp_keepalive_intvl= 1"],
        ["sudo", "sysctl", "-w", "net.ipv4.tcp_keepalive_probes= 1"],
        ["sudo", "sysctl", "-w", "net.ipv4.tcp_keepalive_time= 10"],
        ["sudo","sysctl","--system"]]

    for command in commands:
        subprocess.call(command)


if __name__ == "__main__":
    set_kernel_params()
    check_probable_zombies()
    set_timer()
    execute()
    if kill_list != []:
        print("These are some probable zombie tcp sessions : ")
        for ob in kill_list:
            print(f"local addrress : {ob.laddr} remote address: {ob.raddr} status: {ob.status} process id: {ob.pid} ")
        #kill(kill_list)
