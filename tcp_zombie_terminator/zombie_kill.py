import psutil, time
from scapy.all import sr, IP, TCP, IPv6
from multiprocessing import Process, Queue
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
from colorama import Fore, Back, Style
import logging, os
from datetime import datetime


not_interested = ["LISTEN", "NONE", "SYN_SENT"]
connections_list = []
working = []
zombie_list = []
processes = []
ignored_list = []
result_queue = Queue()
zombie_queue = Queue()
sched = BackgroundScheduler()
cli_mode = False
logging.basicConfig(level=logging.INFO, filename="output.log", filemode="a",  format=' %(levelname)s - %(message)s')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
banner = Fore.RED +  """
  ██████ ▓█████  ▄████▄   █    ██  ██▀███   ██▓   ▒██   ██▒
▒██    ▒ ▓█   ▀ ▒██▀ ▀█   ██  ▓██▒▓██ ▒ ██▒▓██▒   ▒▒ █ █ ▒░
░ ▓██▄   ▒███   ▒▓█    ▄ ▓██  ▒██░▓██ ░▄█ ▒▒██▒   ░░  █   ░
  ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒▓▓█  ░██░▒██▀▀█▄  ░██░    ░ █ █ ▒ 
▒██████▒▒░▒████▒▒ ▓███▀ ░▒▒█████▓ ░██▓ ▒██▒░██░   ▒██▒ ▒██▒
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░▓     ▒▒ ░ ░▓ ░
░ ░▒  ░ ░ ░ ░  ░  ░  ▒   ░░▒░ ░ ░   ░▒ ░ ▒░ ▒ ░   ░░   ░▒ ░
░  ░  ░     ░   ░         ░░░ ░ ░   ░░   ░  ▒ ░    ░    ░  
      ░     ░  ░░ ░         ░        ░      ░      ░    ░  
                ░                                          
"""  + Fore.RESET
sudo_message = Fore.RED + "You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting " + Fore.RESET
line = "------------------------------------------------------------------------------------------------------"
backgorund_message = """The scipt is running ,If you want view logs open output log file in the package folder
                        minimize this terminal and get on with your work. [Press ctrl+c to stop]
                            """


def dispose():
    connections_list.clear()
    working.clear()
    zombie_list.clear()
    processes.clear()
    ignored_list.clear()

def setup():
    for con in psutil.net_connections():
        if con.status not in not_interested:
            connections_list.append(con)
        else: 
            ignored_list.append(con)

def probe_the_port(ip, port, pid, l_ip, l_port,  ip6=False, result_queue=None, zombie_queue=None):
    zombie_count = 0
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for i in range(7):
        if ip6:
            packet = IPv6(dst=ip) / TCP(dport=port, flags="S",)
            ans, unanswered = sr(packet, timeout=1,verbose = False )
        else:
            packet = IP(dst=ip) / TCP(dport=port, flags="S", )
            ans, unanswered = sr(packet, timeout=1, verbose = False)
        if ans:           
            break
        else:
            zombie_count += 1  

    if zombie_count == 7:
        zombie_queue.put((ip, port, l_ip, l_port, pid, current_time))  
    else:
        result_queue.put((ip, port, l_ip, l_port, ans[0][1].sprintf('%TCP.flags%'), current_time))

def start_scan():
    if connections_list:
        for connection in connections_list:
            if str(connection.family) == "AddressFamily.AF_INET6":
                process = Process(target=probe_the_port, args=(connection.raddr[0], connection.raddr[1],connection.pid, connection.laddr[0], connection.laddr[1] , True, result_queue, zombie_queue))
                processes.append(process)
                process.start()
            elif str(connection.family) == "AddressFamily.AF_INET":
                process = Process(target=probe_the_port, args=(connection.raddr[0], connection.raddr[1],connection.pid, connection.laddr[0], connection.laddr[1] , False, result_queue, zombie_queue))
                processes.append(process)
                process.start()

    for process in processes:
        process.join()

    while not result_queue.empty():
        result = result_queue.get()
        working.append(result)

    while not zombie_queue.empty():
        zombie_result = zombie_queue.get()
        zombie_list.append(zombie_result)

#( 'family',  'laddr', 'raddr', 'status', 'pid')

def display():
    if cli_mode != True:
        for work in working:
            logging.info(f"TIME: {work[5]} R_IP: {work[0]} R_PORT: {work[1]} L_IP: {work[2]} L_PORT: {work[3]} RESPONSE: {work[4]} RESULT: working")
        for zombie in zombie_list: 
            logging.info(f"TIME: {zombie[5]} R_IP: {zombie[0]} R_PORT: {zombie[1]} L_IP: {zombie[2]} L_PORT: {zombie[3]} PID: {zombie[4]} RESULT: zombie")
    elif cli_mode:  
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
        print(Fore.BLACK + Back.WHITE + "CURRENTLY RUNNING TCP SESSIONS THAT WILL BE MONITORED  : " + Back.RESET + Fore.RESET + "\n")
        keys = ['R_IP', 'R_PORT', 'L_IP', 'L_PORT', 'STATE', 'TIME']
        print(
            Back.WHITE + Fore.BLACK +
            f"{keys[5]:<29} "
            f"{keys[0]:<20} "
            f"{keys[1]:<23} "
            f"{keys[2]:<22} "
            f"{keys[3]:<25} "
            f"{keys[4]:<5} "
            +
            Back.RESET + Fore.RESET
        )
        for con in connections_list:
            #print(f"R_IP: {con.raddr[0]} R_PORT: {con.raddr[1]} L_IP: {con.laddr[0]} L_PORT: {con.laddr[1]} STATE: {con.status}")
            print(
                Back.BLACK + Fore.WHITE +
                f"{current_time:25} "
                f"{con.raddr[0]:<25} "
                f"{con.raddr[1]:<20} "
                f"{con.laddr[0]:<25} "
                f"{con.laddr[1]:<20} "
                f"{con.status:<20} "
                +
                Back.RESET + Fore.RESET
            )

        keys = ['R_IP', 'R_PORT', 'L_IP', 'L_PORT', 'STATE', 'TIME', 'RESPONSE']
        print("\n")
        print(Fore.BLACK + Back.WHITE + "AFTER RUNNING DIAGNOSIS  : " + Back.RESET + Fore.RESET + "\n")
        
        print(
            Back.WHITE + Fore.BLACK +
            f"{keys[5]:<29} "
            f"{keys[0]:<20} "
            f"{keys[1]:<23} "
            f"{keys[2]:<22} "
            f"{keys[3]:<20} "
            f"{keys[6]:<22} "
            f"{keys[4]:<5} "
            +
            Back.RESET + Fore.RESET
        )
        for work in working:
            print(
                Back.BLACK + Fore.GREEN +
                f"{work[5]:<25} "
                f"{work[0]:<25} "
                f"{work[1]:<20} "
                f"{work[2]:<25} "
                f"{work[3]:<20} "
                f"{work[4]:<20} "
                "working" +
                Back.RESET + Fore.RESET
            )
        
        if len(zombie_list) != 0:
            keys = ['R_IP', 'R_PORT', 'L_IP', 'L_PORT', 'STATE', 'TIME', 'PID']
            print(
            Back.WHITE + Fore.BLACK +
            f"{keys[5]:<29} "
            f"{keys[0]:<20} "
            f"{keys[1]:<23} "
            f"{keys[2]:<22} "
            f"{keys[3]:<20} "
            f"{keys[6]:<22} "
            f"{keys[4]:<20} "
            +
            Back.RESET + Fore.RESET
        )
        for zombie in zombie_list: 
            #print(Back.BLACK + Fore.RED+ f"TIME: {zombie[5]} R_IP: {zombie[0]} R_PORT: {zombie[1]} L_IP: {zombie[2]} L_PORT: {zombie[3]} PID: {zombie[4]} RESULT: zombie" +  Back.RESET + Fore.RESET)
            print(
                Back.BLACK + Fore.RED +
                f"{zombie[5]:<35} "
                f"{zombie[0]:<25} "
                f"{zombie[1]:<20} "
                f"{zombie[2]:<25} "
                f"{zombie[3]:<20} "
                f"{zombie[4]:<20} "
                "ZOMBIE" +
                Back.RESET + Fore.RESET
            )
        print("\n")


def kill():
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
    if len(zombie_list) != 0:
        if cli_mode:
            print(Fore.BLACK + Back.WHITE + "AFTER PERFORMING CLEANUP  : " + Back.RESET + Fore.RESET + "\n")
            keys = ['R_IP', 'R_PORT', 'L_IP', 'L_PORT', 'STATE', 'TIME', 'PID']
            print(
            Back.WHITE + Fore.BLACK +
            f"{keys[5]:<29} "
            f"{keys[0]:<10} "
            f"{keys[1]:<13} "
            f"{keys[2]:<12} "
            f"{keys[3]:<10} "
            f"{keys[6]:<12} "
            f"{keys[4]:<10} "
            +
            Back.RESET + Fore.RESET
        )
        for zombie in zombie_list:
            pid = zombie[4]
            if pid is not None:
                s_pid = str(pid)
                subprocess.call(["kill", "-9", s_pid])
                if  cli_mode != True:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    logging.info(f"TIME: {current_time} R_IP: {zombie[0]} R_PORT: {zombie[1]} L_IP: {zombie[2]} L_PORT: {zombie[3]} PID: {zombie[4]} STATE: KILLED")
                elif cli_mode:
                    print(
                Back.BLACK + Fore.RED +
                f"{zombie[5]:<25} "
                f"{zombie[0]:<15} "
                f"{zombie[1]:<10} "
                f"{zombie[2]:<15} "
                f"{zombie[3]:<10} "
                f"{zombie[4]:<10} "
                "KILLED" +
                Back.RESET + Fore.RESET
            )
            else:
                if cli_mode != True:
                    logging.info(f"TIME: {current_time} R_IP: {zombie[0]} R_PORT: {zombie[1]} L_IP: {zombie[2]} L_PORT: {zombie[3]} PID: {zombie[4]} STATE: KILL NOT SUCCESSFUL")
                elif cli_mode:
                    print(
                Back.BLACK + Fore.RED +
                f"{zombie[5]:<25} "
                f"{zombie[0]:<15} "
                f"{zombie[1]:<10} "
                f"{zombie[2]:<15} "
                f"{zombie[3]:<10} "
                f"{zombie[4]:<10} "
                "KILL NOT POSSIBLE NO PID" +
                Back.RESET + Fore.RESET
            )
    else:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if cli_mode != True:
            logging.info(f"NO ZOMBIES DETECTED. TIME : {current_time}")
        else:
            print(Back.GREEN + Fore.WHITE + f"NO ZOMBIES DETECTED. TIME : {current_time}" + Back.RESET + Fore.RESET)



def z_kill():
    setup()
    start_scan()
    display()
    kill()
    dispose()

def run(cli = True, silent = False):
    global cli_mode
    if os.geteuid() != 0:
        print(banner + "\n" + line + "\n" + sudo_message +"\n"+  line) 
        exit()
    if cli == True and silent == False:
        cli_mode = True
        print(banner + "\n" + line)
        z_kill()
    if cli == False and silent == False:
        print(banner + "\n" + line + "\n" + backgorund_message + "\n" + line)
        z_kill()
        sched.add_job(z_kill, 'interval', seconds=20)
        sched.start()
        while True:
            time.sleep(1)
    if cli == False and silent == True:
        z_kill()
        sched.add_job(z_kill, 'interval', seconds=20)
        sched.start()
        while True:
            time.sleep(1)

if __name__ == "__main__":
	run(True, False )
