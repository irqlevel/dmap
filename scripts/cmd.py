# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import subprocess
import os
from datetime import datetime
import logging.config
import logging
import uuid
import threading
import copy
import time
import sys
import inspect
import re

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

def exec_cmd(cmd, output = False, elog = None):
    args = cmd.split()
    if elog:
        elog.info("EXEC:" + cmd + ":" + str(args))

    if output:
        process = subprocess.Popen(args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    else:
        process = subprocess.Popen(args)

    stdout, stderr = process.communicate()
    process.wait()

    if elog:
        elog.info("EXEC:stdout:" + str(stdout))
        elog.info("EXEC:stderr:" + str(stderr))
        elog.info("EXEC:" + cmd + ":" + str(args) + ":rc=" + str(process.returncode))
    return (process.returncode, stdout, stderr)

class StdFp():
    def __init__(self, fp, log_extra, elog = None):
        self.fp = fp
        self.lines = []
        self.lock = threading.Lock()
        self.log_extra = log_extra
        self.elog = elog

    def append(self, l):
        self.lock.acquire()
        try:
            lp = l.replace("\n", "")
            if self.elog:
                self.elog.info(self.log_extra + ":" + lp)
            self.lines.append(lp)
        except Exception as e:
            if self.elog:
                self.elog.exception(str(e))
        finally:
            self.lock.release()

    def get_lines(self):
        lines = []
        self.lock.acquire()
        try:
            lines = copy.deepcopy(self.lines)
        except Exception as e:
            if self.elog:
                self.elog.exception(str(e))
        finally:
            self.lock.release()

        return lines

class StdThread(threading.Thread):
    def __init__(self, std_fp):
        threading.Thread.__init__(self)
        self.std_fp = std_fp
        self.stopping = False
    def run(self):
        while not self.stopping:
            l = self.std_fp.fp.readline()
            if l == '':
                break
            self.std_fp.append(l)

class Cmd():
    def __init__(self, cmd, throw = False, elog = None):
        self.cmd = cmd
        self.stdout = None
        self.stderr = None
        self.throw = throw
        self.elog = elog

    def run(self):
        if self.elog != None:
            self.elog.info("CMD:" + self.cmd)

        process = subprocess.Popen(self.cmd, shell=True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

        self.stdout = StdFp(process.stdout, "CMD:stdout", elog = self.elog)
        self.stderr = StdFp(process.stderr, "CMD:stderr", elog = self.elog)

        self.stderr_t = StdThread(self.stderr)
        self.stdout_t = StdThread(self.stdout)

        self.stdout_t.start()
        self.stderr_t.start()

        process.wait()

        self.stdout_t.join()
        self.stderr_t.join()

        self.rc = process.returncode

        #log.info("CMD:" + self.cmd + ":stdout:" + self.stdout.out)
        #log.info("CMD:" + self.cmd + ":stderr:" + self.stderr.out)
        if self.rc == 0:
           if self.elog != None:
                self.elog.info("CMD:" + self.cmd + ":rc:" + str(self.rc))
        else:
           if self.elog != None:
                self.elog.error("CMD:" + self.cmd + ":rc:" + str(self.rc))

        if self.rc != 0 and self.throw:
            raise Exception("CMD:" + self.cmd + ":rc:" + str(self.rc))

def exec_cmd2(cmd, throw = False, elog = None):
    c = Cmd(cmd, throw = throw, elog = elog)
    c.run()
    return c.rc , c.stdout.lines, c.stderr.lines, c

def exec_cmd2_list(cmds, elog = None):
    rcs = []
    for cmd in cmds:
        c = Cmd(cmd, elog = elog)
        c.run()
        rcs.append(c.rc)
    return rcs

if __name__=="__main__":
    exec_cmd2("ps ax")
