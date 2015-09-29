#!/usr/local/bin/python3.4

import logging
import paramiko
import socket
import functools
import subprocess


def execute_cmd_over_ssh(host_ip, host_username, host_password, command):
    """
    the function is to execute the command over ssh Protocol
    Return 0 - Success
    Return 257 - unknown exception
    Return other - the command return code

    return formart: (returncode, output in list)
    """
    _METHOD_ = "executeCMDoverSSH"
    logging.info("ENTER %s::address=%s userid=%s command=%s",
                 _METHOD_, host_ip, host_username, command)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host_ip, username=host_username,
                       password=host_password, timeout=30)
        (stdin, stdout, stderr) = client.exec_command(command)
        stdin.close()
        rc = stdout.channel.recv_exit_status()
        message = []
        if rc == 0:
            for line in stdout.read().decode('ascii').splitlines():
                message.append(line)
        else:
            for line in stderr.read().decode('ascii').splitlines():
                message.append(line)

        logging.info(
            "EXIT %s:: returncode=%s, message=%s", _METHOD_, rc, message)
        return (rc, message)
    except paramiko.AuthenticationException:
        logging.error("%s::userid/password combination not valid. address=%s userid=%s",
                      _METHOD_, host_ip, host_username)
        raise
    except socket.timeout:
        logging.error(
            "%s::Connection timed out. Address=%s", _METHOD_, host_ip)
        raise
    except TimeoutError:
        logging.error(
            "%s::Connection timed out. Address=%s", _METHOD_, host_ip)
        raise
    except Exception as e:
        logging.error(
            "%s::Exception in function. Address=%s, Exception=%s", _METHOD_, host_ip, e)
        return (257, None)
    finally:
        client.close()


def entry_exit(excludeIndex=[], excludeName=[]):
    """
    it's a decorator that to add entry and exit log for a function

    input:
    excludeIndex -- the index of params that you don't want to be record
    excludeName -- the name of dictionary params that you don't wnat to be record
    """
    def f(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            argsForPrint = []
            tmp_index = 0
            arg_len = len(args)
            while tmp_index < arg_len:
                if tmp_index not in excludeIndex:
                    argsForPrint.append(args[tmp_index])
                tmp_index += 1
            kwargsForPrint = {}
            for a in kwargs:
                if a in excludeName:
                    continue
                else:
                    kwargsForPrint[a] = kwargs[a]

            logging.info("%s::Entry params %s %s", func.__name__, "{}".format(
                argsForPrint), "{}".format(kwargsForPrint))
            result = func(*args, **kwargs)
            logging.info("%s::Exit %s ", func.__name__, "{}".format(result))
            return result
        return wrapper
    return f


def execute_cmd_on_local(command):
    """
    the funcjtion is to execute command on local server

    return 0 - success
    return other - failed
    """

    _METHOD_ = "executeCMDOnLocal"
    logging.info("ENTER %s::", _METHOD_)
    p = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rc = p.wait()
    message = []
    if rc == 0:
        for line in p.stdout.read().decode('ascii').splitlines():
            message.append(line)
    else:
        for line in p.stderr.read().decode('ascii').splitlines():
            message.append(line)
    p.stdout.close()
    p.stderr.close()
    logging.info("EXIT %s:: returncode=%s, message=%s", _METHOD_, rc, message)
    return (rc, message)
