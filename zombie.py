import psutil
import threading
import os
import signal
import queue, subprocess

p_z = []
timers = []
kill_list = []
termination_queue = queue.Queue()

def check_established_cases():
    pass

def eliminate_without_pid():
    pass

def check_probable_zombies():
    
    p_z.clear()
    for c in psutil.net_connections(kind="tcp"):
        if c.status in ["FIN_WAIT2", "FIN_WAIT1", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT"]:
            p_z.append(c)
            print("done")
        elif c.status == "ESTABLISHED":
            check_established_cases()
        

    if not p_z:
        print("None")

def set_timer():
    timers.clear()
    if p_z:
        for p in p_z:
            timers.append(threading.Timer(5.0, z_kill, args=(p,)))

def execute():
    for timer in timers:
        timer.start()

def z_kill(zombie):
    kill_list.append(zombie)

def add_to_termination_queue():
    while True:
        if kill_list:
            zombie = kill_list.pop(0)
            termination_queue.put(zombie)

def terminate_from_queue():
    while True:
        zombie = termination_queue.get()
        pid = zombie.pid
        if pid != None:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError as e:
                print(f"Failed to terminate process with PID {pid}: {e}")
            finally:
                termination_queue.task_done()
        elif pid == None:
            port = zombie.laddr[1]
            subprocess.call(["sudo", "lsof",  "-i,", port])

if __name__ == "__main__":
    check_probable_zombies()
    set_timer()
    execute()
    

