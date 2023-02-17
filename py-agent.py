import sys
import time
import subprocess
import os
import datetime

def log(msg):
    now = datetime.datetime.now()
    print("[%s] %s" % (now.strftime("%Y-%m-%d %H:%M:%S"), msg))

# Expected usage: ./python py-agent.py <path-to-executable> <timeout-in-seconds-before-executing> <executable-name> <executable-arguments>
# Example: python py-agent.py "C:\Users\arthu\AppData\Local\Microsoft\WindowsApps" 5 mspaint.exe
def main():
    path = sys.argv[1]
    timeout = int(sys.argv[2])
    exec_cmd = sys.argv[3]
    exec_args = " ".join(sys.argv[4:])
    log("Pre timeout: %d" % timeout)
    log("Executable path: %s" % path)
    log("Executable name: %s" % exec_cmd)
    log("Execution arguments: %s" % exec_args)

    log("Moving to executable location at '%s'" % path)
    os.chdir(path)

    log("Performing pre-sleep for %d seconds ..." % timeout)
    time.sleep(timeout)

    while (True):
        log("Starting process: '%s'" % exec_cmd)
        p = subprocess.Popen((exec_cmd, exec_args))
        p.wait()
        log("Process terminated with code: %d" % p.returncode)

        # If the process terminated normally give more time to close py-agent for normal shutdown
        restart_timeout = 30 if p.returncode == 0 else 5
        log("Restarting process after %ds timeout ..." % restart_timeout)
        time.sleep(restart_timeout)



if __name__ == "__main__":
    main()
