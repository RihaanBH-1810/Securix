import psutil
import threading
import os
import signal
import queue
import subprocess

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
        if c.status in ["FIN_WAIT2", "FIN_WAIT1", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT" and c.laddr[1] > 1023]:
            p_z.append(c)
            print("done")
        elif c.status == "ESTABLISHED":
            check_established_cases()

    if not p_z:
        print("None")


def set_timer():
    timers.clear()

    for p in p_z:
        timers.append(threading.Timer(5.0, z_kill(p)))


def execute():
    for timer in timers:
        timer.start()


def z_kill(zombie):
    if zombie.status in ["FIN_WAIT2", "FIN_WAIT1", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT"]:
        kill_list.append(zombie)


def kill(kill_list):
    for con in kill_list:
        if con.laddr.family == psutil.AF_INET and con.laddr.port == 80:

            
            if con.pid == None:
                interface = con.laddr.ifname

                interface_address = psutil.net_if_addrs()[interface][0].address

                print("Interface name:", interface)
                print("Interface address:", interface_address)
                subprocess.call(["sudo", "tcpkill", "-i", "any", "port", con.laddr[1]])
            else:
                pid = str(con.pid)
                subprocess.call(["sudo", "kill", "-9", pid])


if __name__ == "__main__":
    check_probable_zombies()
    set_timer()
    execute()
    if kill_list != []:
        kill(kill_list)
