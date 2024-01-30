# SECURIX

### A powerful python script designed to automatically detect and terminate unwanted, resource-consuming zombie TCP sessions on networks. It scans all open tcp sessions and probes them for a certain amount of time, in case of no response received, the session is marked as zombie and later terminated. Multiprocessing is incorporated in order to speed up the process by probing the multiple ports at the same time. Overall, it's a very efficient and seamless process. It is a complete solution with near to hundred percent accuracy.

#### There are two modes the user can choose from:
* CLI : The user can view the entire process in the form of a table from the terminal.
* BACKGROUND: The script is ran in the background and repeated after a certain amount of time in order to prevent accumualtion of zombie sessions. The details are logged into a file so that the admin and view it later.



# How to run:

* run cmd : ```source/py_run.sh```
*  and to finally run it : ```zombie_kill```

