# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import paramiko
import os
import sys
import time
import inspect
import logging

#currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
#parentdir = os.path.dirname(currentdir)
#sys.path.insert(0,parentdir) 

from cmd import StdFp, StdThread

def ssh_cmd(ssh, cmd, throw = False, log = None):
    if log:
        log.info(ssh.get_tag() + cmd)
    chan = None
    out_lines = []
    err_lines = []
    rc = 777
    try:
        chan = ssh.get_transport().open_session()
        chan.get_pty()
        chan.exec_command(cmd)

        stdout = StdFp(chan.makefile(), ssh.get_tag() + "stdout", elog = log)
        stderr = StdFp(chan.makefile_stderr(), ssh.get_tag() + "stderr", elog = log)

        stderr_t = StdThread(stderr)
        stdout_t = StdThread(stdout)

        stdout_t.start()
        stderr_t.start()

        rc = chan.recv_exit_status()
        stdout_t.join()
        stderr_t.join()
        out_lines = stdout.lines
        err_lines = stderr.lines

        if rc == 0:
            if log:
                log.info(ssh.get_tag() + cmd + ":rc:" + str(rc))
        else:
            if log:
                log.error(ssh.get_tag() + cmd + ":rc:" + str(rc))
    except Exception as e:
        if log:
            log.exception(str(e))
    finally:
        if chan != None:
            try:
                chan.shutdown(2)
            except Exception as e:
                if log:
                    log.exception(str(e))

    if rc != 0 and throw:
        raise Exception(ssh.get_tag() + cmd + ":rc:" + str(rc))

    return rc, out_lines, err_lines

class SshExec:
    def __init__(self, log, host, user, password = None, key_file = None, timeout = None, ftp = False):
        self.host = host
        self.user = user
        self.password = password
        self.key_file = key_file
        self.log = log
        self.timeout = timeout

        if self.key_file != None:
            self.pkey = paramiko.RSAKey.from_private_key_file(self.key_file)
        else:
            self.pkey = None

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.host, username=self.user, password = self.password, pkey=self.pkey, timeout = self.timeout)

        if ftp:
            self.ftp = self.ssh.open_sftp()
        else:
            self.ftp = None
        self.log.info(self.get_tag() + 'opened ssh to host ' + self.host)
        self.ssh.get_tag = self.get_tag

    def cmd(self, cmd, throw = True):
        return ssh_cmd(self.ssh, cmd, throw = throw, log = self.log)

    def get_tag(self):
        return "SSH:" + self.host + ":"

    def file_get(self, remote_file, local_file):
        self.log.info(self.get_tag() + "GETFILE:" + str(self.host) + " remote:" + remote_file + " local:" + local_file)
        self.ftp.get(remote_file, local_file)
        self.log.info(self.get_tag() + "GETFILE:completed")
    def file_put(self, local_file, remote_file):
        self.log.info(self.get_tag() + "PUTFILE:" + str(self.host) + " local:" + local_file + " remote:" + remote_file)
        self.ftp.put(local_file, remote_file)
        self.log.info(self.get_tag() + "PUTFILE:completed")
    def file_getcwd(self):
        return self.ftp.getcwd()
    def file_chdir(self, path):
        return self.ftp.chdir(path)
    def close(self):
        try:
            if self.ftp != None:
                self.ftp.close()
        except:
            pass
        try:
            self.ssh.close()
        except:
            pass

class SshUser():
    def __init__(self, log, host, user, password = None, key_file = None, timeout = None, ftp = False):
        self.log = log
        self.host = host
        self.user = user
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.ftp = ftp

def ssh_by_suser(suser):
    s = SshExec(suser.log, suser.host, suser.user, password = suser.password, key_file = suser.key_file, timeout = suser.timeout, ftp = suser.ftp)
    return s

def ssh_exec(suser, cmd, throw = True):
    s = ssh_by_suser(suser)
    rs = None
    try:
        rs = s.cmd(cmd, throw = throw)
    finally:
        s.close()
    return rs

def ssh_file_get(suser, remote_file, local_file):
    s = ssh_by_suser(suser)
    try:
        s.file_get(remote_file, local_file)
    finally:
        s.close()

def ssh_file_put(suser, local_file, remote_file):
    s = ssh_by_suser(suser)
    try:
        s.file_put(local_file, remote_file)
    finally:
        s.close()

if __name__ == '__main__':
    ssh = SshExec(None, "10.30.18.211", "root", "1q2w3es5")
    ssh.cmd("ps aux")
