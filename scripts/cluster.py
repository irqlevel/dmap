import logging
import os
import sys
import argparse

from cmd import exec_cmd2 as cmd
from ssh import SshExec as ssh

log = logging.getLogger()
log.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

def run(cmd, user, password, key, verbose, nodes):
    if cmd == "install":
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("sudo apt-get update")
            s.cmd("sudo apt-get install -y keyutils git gcc make")
            s.cmd("git clone https://github.com/irqlevel/dmap ~/dmap")
            s.cmd("cd ~/dmap && make")
            s.cmd("sudo iptables -F")
    elif cmd == "start":
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("cd ~/dmap && sudo scripts/start.sh")
            s.cmd("sudo ls -al /sys/fs/dmap/")
            s.cmd("echo " + n + " 8111 | sudo tee /sys/fs/dmap/start_server")
        for n in nodes:
            for m in nodes:
                if n != m:
                    s = ssh(log, n, user, password=password, key_file=key)
                    s.cmd("echo " + m + " 8111 | sudo tee /sys/fs/dmap/add_neighbor", throw=False)
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("sudo cat /sys/fs/dmap/neighbors")

    elif cmd == "stop":
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("cd ~/dmap && sudo scripts/stop.sh")
    elif cmd == "uninstall":
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("cd ~/dmap && sudo scripts/stop.sh", throw = False)
            s.cmd("sudo rm -rf ~/dmap")
    elif cmd == "info":
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("hostname")
            s.cmd("ifconfig")
    elif cmd == "trace":
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("sudo cat /sys/kernel/debug/tracing/trace")
    elif cmd == "node-info":
        for n in nodes:
            s = ssh(log, n, user, password=password, key_file=key)
            s.cmd("sudo cat /sys/fs/dmap/id")
            s.cmd("sudo cat /sys/fs/dmap/nr_keys")
            s.cmd("sudo cat /sys/fs/dmap/neighbors")
    else:
        raise Exception("Unknown cmd %s", cmd)

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
    parser.add_argument("-u", "--user", action="store", help="user")
    parser.add_argument("-p", "--password", action="store", help="password")
    parser.add_argument("-k", "--key", action="store", help="access key")
    parser.add_argument("command", action="store", help="command")
    parser.add_argument("nodes", action="store", help="nodes", nargs="+")
    args = parser.parse_args()
    run(args.command, args.user, args.password, args.key, args.verbose, args.nodes)
