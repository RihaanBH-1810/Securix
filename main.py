import tcp_zombie_terminator.zombie_kill
def once():
    tcp_zombie_terminator.zombie_kill.run(True,False)
def timer():
    tcp_zombie_terminator.zombie_kill.run(False,False)
def background():
    tcp_zombie_terminator.zombie_kill.run(False,True)
def set_params():
    tcp_zombie_terminator.zombie_kill.set_kernel_params()