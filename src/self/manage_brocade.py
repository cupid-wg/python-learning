#!/usr/local/bin/python3.4

import logging
import re
import pexpect
import ssh_utils

Timeout = 120
ROOT_PROMPT = '#'
Timeout_CmdRep = 15
GET_VERSION_COMMAND = "version show | grep OS"
CURRENT_VERSION_TAG = "OS"


SNMPTRAPD_CONF_FILE = "snmptrapd.conf"
SNMP_CONF_DEFAULT_POSITION = "/etc/snmp"


def subscribe(address, userid, password, receiver_address):
    """
    This function will call snmpConfig to configure the snmpv1 in the brocade switch
    to submit the Traps to the receiver nagios server
    The return values:
    '0' --> success
    '1' --> connection to the brocade switch failed
    '2' --> invalid userid/password
    '4' --> snmpConfig failed to add the target server in snmpv3
    """
    _METHOD_ = "manage_brocade.subscribe"
    logging.info("ENTER %s::address=%s userid=%s receiver=%s",
                 _METHOD_, address, userid, receiver_address)
    switch_admin = userid + "> "
    try:
        ssh_conn_child = pexpect.spawn(
            " ".join(["ssh -o StrictHostKeyChecking=false -l", userid, address]))
        ssh_conn_child.timeout = Timeout
        ssh_conn_index = ssh_conn_child.expect(
            ['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
        if ssh_conn_index != 0:
            raise BrocadeException(1)
        ssh_conn_child.sendline(password)
        # if shell prompts for password again, the password / user combination
        # wrong
        ssh_conn_index = ssh_conn_child.expect(
            [switch_admin, "(?i)password:", ROOT_PROMPT])
        if ssh_conn_index == 1:
            raise BrocadeException(2)
        elif ssh_conn_index != 0:
            raise BrocadeException(3)
        ssh_conn_child.send("snmpconfig --enable snmpv3\r")
        ssh_conn_index = ssh_conn_child.expect(
            switch_admin, timeout=Timeout_CmdRep)
        if ssh_conn_index != 0:
            raise BrocadeException(4, "Failed to enable snmpv3")
        # get snmp definiton for brocade:
        (snmp_user, snmp_user_index, snmp_auth_password,
         snmp_priv_password) = _get_snmp_config()
        # first check if the snmp user and snmp trap receiver is already set
        ssh_conn_child.sendline("snmpconfig --show snmpv3")
        ssh_conn_index = ssh_conn_child.expect(
            [switch_admin, pexpect.EOF, pexpect.TIMEOUT], timeout=Timeout_CmdRep)
        if ssh_conn_index != 0:
            raise BrocadeException(
                4, "Failed to list snmp configure with return code " + str(ssh_conn_index))
        output_lines = ssh_conn_child.before.decode('ascii').split("\r\n")
        user_num = -1
        is_recv_defined = False
        tmp_index = 0
        username_to_modify = None
        while tmp_index < len(output_lines):
            line = output_lines[tmp_index]
            if "User" in line and "Trap" not in line and (line.split()[3] == snmp_user or line.split()[1] == snmp_user_index):
                user_num = line.split()[1]
                username_to_modify = line.split()[3]
            if "Trap Entry" in line and len(line.split()) == 4 and line.split()[3] == receiver_address:
                is_recv_defined = True
                logging.info(
                    "%s::snmp already defined on %s for receiver %s", _METHOD_, address, receiver_address)
                break
            tmp_index += 1

        ssh_conn_child.send("snmpconfig --set snmpv3\r")
        expect_result = ssh_conn_child.expect("SNMP Informs Enabled")
        if expect_result != 0:
            raise BrocadeException(
                4, "Assume get message for inform setting but now it's " + ssh_conn_child.before.decode('ascii').split("\r\n"))
        # disable inform, we just use trap
        ssh_conn_child.sendline("f")
        go_to_password_change = False
        while True:
            expect_result = ssh_conn_child.expect(["User \(r.\): \[(.+)\]", "Auth Protocol", "New Auth Passwd", "Verify Auth Passwd",
                                                   "Priv Protocol", "New Priv Passwd", "Verify Priv Passwd", "SNMPv3 trap recipient configuration", pexpect.EOF, pexpect.TIMEOUT])
            # input name if it's the one to be modify
            if expect_result == 0 and username_to_modify == ssh_conn_child.match.group(1).decode('ascii'):
                ssh_conn_child.send(snmp_user)
                go_to_password_change = True
            if go_to_password_change and expect_result == 1:
                # chosse auth type, MD5 is 1 in default
                ssh_conn_child.send("1")
            if go_to_password_change and (expect_result == 2 or expect_result == 3):
                ssh_conn_child.send(snmp_auth_password)
            if go_to_password_change and (expect_result == 5 or expect_result == 6):
                ssh_conn_child.send(snmp_priv_password)
                go_to_password_change = False if expect_result == 6 else True
            if go_to_password_change and expect_result == 4:
                ssh_conn_child.send("1")
            if expect_result == 7:
                break
            ssh_conn_child.send("\r")

        go_to_recv_define = False
        # the user,level,port define message will appear for each defined trap,
        # so that we have to set flag to identify just pass or enter data to
        # modify
        while True:
            expect_result = ssh_conn_child.expect(["Trap Recipient's IP address :.*\[(.+)\]", "UserIndex",
                                                   "Trap recipient Severity level", "Trap recipient Port", switch_admin, pexpect.EOF, pexpect.TIMEOUT])
            if expect_result == 0 and ((is_recv_defined and receiver_address == ssh_conn_child.match.group(1).decode('ascii')) or (not is_recv_defined and not go_to_recv_define and "0.0.0.0" == ssh_conn_child.match.group(1).decode('ascii'))):
                ssh_conn_child.send(receiver_address)
                go_to_recv_define = True
            if expect_result == 1 and go_to_recv_define:
                ssh_conn_child.send(user_num)
            if expect_result == 3 and go_to_recv_define:
                # modify flag
                is_recv_defined = True
                go_to_recv_define = False
            if expect_result == 4:
                break
            ssh_conn_child.send("\r")
        # run snmpget command to get the engine_id
        (rc, message) = ssh_utils.execute_cmd_on_local(" ".join(
            ["snmpget", "-v", "3", "-u", snmp_user, "-l", "authPriv", "-a", "MD5", "-A", snmp_auth_password, "-x", "DES", "-X", snmp_priv_password, address, "1.3.6.1.6.3.10.2.1.1.0"]))
        if rc != 0:
            raise BrocadeException(
                4, "failed to get engine id from switch with message = " + message)
        engine_id = ""
        for line in message:
            engine_id += line if line.rfind(":") == - \
                1 else line[line.rfind(":") + 1:]
        engine_id = "0x" + engine_id.replace(" ", "")
        (rc) = update_snmp_v3_conf(
            engine_id, snmp_user, "MD5", snmp_auth_password, "DES", snmp_priv_password, 1)
        if rc == 0:
            (rc, message) = ssh_utils.execute_cmd_on_local(
                "service snmptrapd restart")
            if rc != 0:
                logging.error(
                    "%s::restart snmptrap service failed , message = " + message)
                return 3
        else:
            logging.error(
                "%s::update snmptrap conf failed, won't restart snmptrapd service")
            return 3
        logging.info("%s::The Trap subcribe has been done. address=%s userid=%s targe=%s",
                     _METHOD_, address, userid, receiver_address)
        return 0
    except BrocadeException as e:
        if e.error_code == 1:
            logging.error(
                "%s::connection to device failed. address=%s userid=%s", _METHOD_, address, userid)
            return 1
        elif e.error_code == 2:
            logging.error(
                "%s::userid/password combination not valid. address=%s userid=%s", _METHOD_, address, userid)
            return 2
        elif e.error_code == 3:
            logging.error(
                "%s::The device is not a brocade switch. address=%s userid=%s", _METHOD_, address, userid)
            return 4
        elif e.error_code == 4:
            logging.error(
                "%s::failed to get engine id from switch. address=%s userid=%s", _METHOD_, address, userid)
            return 4
        else:
            logging.error(
                "%s:: exception error", _METHOD_ + "::" + str(e.error_message))
            return 3
    except Exception as e:
        #print("%s:: exception error", _METHOD_+"::"+str(e))
        logging.error("%s:: exception error", _METHOD_ + "::" + str(e))
        return 3
    finally:
        ssh_conn_child.close()


def unsubscribe(address, userid, password, receiver_address):
    """
    Unsubscribes the Nagios server that the system won't receive
    the brocade Traps
    Returned values:
    '0' --> success
    '1' --> connection failed
    '2' --> invalid userid/password combination
    '5' --> after login the Brocade switch, the snmpConfig operation failed
    """
    _METHOD_ = "manage_brocade.unsubscribe"

    Timeout = 120
    logging.info("ENTER %s::address=%s userid=%s receiver=%s",
                 _METHOD_, address, userid, receiver_address)
    switch_admin = userid + "> "
    try:
        ssh_conn_child = pexpect.spawn(
            " ".join(["ssh -o StrictHostKeyChecking=false -l", userid, address]))
        ssh_conn_child.timeout = Timeout
        ssh_conn_index = ssh_conn_child.expect(
            ['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
        if ssh_conn_index != 0:
            raise BrocadeException(1)
        ssh_conn_child.sendline(password)
        # if shell prompts for password again, the password / user combination
        # wrong
        ssh_conn_index = ssh_conn_child.expect(
            [switch_admin, "(?i)password:", ROOT_PROMPT])
        if ssh_conn_index == 1:
            raise BrocadeException(2)
        elif ssh_conn_index != 0:
            raise BrocadeException(3)
        ssh_conn_child.send("snmpconfig --set snmpv3\r")
        expect_result = ssh_conn_child.expect("SNMP Informs Enabled")
        if expect_result != 0:
            raise BrocadeException(
                4, "Assume get message for inform setting but now it's " + ssh_conn_child.before.decode('ascii').split("\r\n"))
        # disable inform, we just use trap
        ssh_conn_child.sendline("f")
        # no need to do action in user config
        while True:
            expect_result = ssh_conn_child.expect(["User \(r.\): \[(.+)\]", "Auth Protocol", "New Auth Passwd", "Verify Auth Passwd",
                                                   "Priv Protocol", "New Priv Passwd", "Verify Priv Passwd", "SNMPv3 trap recipient configuration", pexpect.EOF, pexpect.TIMEOUT])
            if expect_result == 7:
                break
            ssh_conn_child.send("\r")

        while True:
            expect_result = ssh_conn_child.expect(["Trap Recipient's IP address :.*\[(.+)\]", "UserIndex",
                                                   "Trap recipient Severity level", "Trap recipient Port", switch_admin, pexpect.EOF, pexpect.TIMEOUT])
            if expect_result == 0 and receiver_address == ssh_conn_child.match.group(1).decode('ascii'):
                ssh_conn_child.send("0.0.0.0")
            if expect_result == 4:
                break
            ssh_conn_child.send("\r")

        (snmp_user, snmp_user_index, snmp_auth_password,
         snmp_priv_password) = _get_snmp_config()
        (rc, message) = ssh_utils.execute_cmd_on_local(" ".join(
            ["snmpget", "-v", "3", "-u", snmp_user, "-l", "authPriv", "-a", "MD5", "-A", snmp_auth_password, "-x", "DES", "-X", snmp_priv_password, address, "1.3.6.1.6.3.10.2.1.1.0"]))
        if rc != 0:
            raise BrocadeException(
                4, "failed to get engine id from switch with message = " + message)
        engine_id = ""
        for line in message:
            engine_id += line if line.rfind(":") == - \
                1 else line[line.rfind(":") + 1:]
        engine_id = "0x" + engine_id.replace(" ", "")

        (rc) = update_snmp_v3_conf(
            engine_id, snmp_user, "MD5", snmp_auth_password, "DES", snmp_priv_password, 2)
        logging.info("%s::The Trap subcribe has been done. address=%s userid=%s targe=%s",
                     _METHOD_, address, userid, receiver_address)
        if rc == 0:
            (rc, message) = ssh_utils.execute_cmd_on_local(
                "service snmptrapd restart")
            if rc != 0:
                logging.error(
                    "%s::restart snmptrap service failed , message = " + ''.join(message))
                return 3
        else:
            logging.error(
                "%s::update snmptrap conf failed, won't restart snmptrapd service")
            return 3
        logging.info(
            "%s:: has been completed successfully. Address=%s", _METHOD_, address)
        return 0
    except BrocadeException as e:
        if e.error_code == 1:
            logging.error(
                "%s::connection to device failed. address=%s userid=%s", _METHOD_, address, userid)
            return 1
        elif e.error_code == 2:
            logging.error(
                "%s::userid/password combination not valid. address=%s userid=%s", _METHOD_, address, userid)
            return 2
        elif e.error_code == 3:
            logging.error(
                "%s::The device is not a brocade switch. address=%s userid=%s", _METHOD_, address, userid)
            return 5
        elif e.error_code == 4:
            logging.error(
                "%s::failed to get engine id from switch. address=%s userid=%s", _METHOD_, address, userid)
            return 5
        else:
            logging.error(
                "%s:: exception error", _METHOD_ + "::" + str(e.error_message))
            return 3
    except Exception as e:
        #print("%s:: exception error", _METHOD_+"::"+str(e))
        logging.error("%s:: exception error", _METHOD_ + "::" + str(e))
        return 3

    finally:
        ssh_conn_child.close()


def _get_snmp_config():
    _METHOD_ = "_get_snmp_config"
    snmp_user = "test"
    snmp_user_index = "6"
    snmp_auth_password = 'passw0rd'
    snmp_priv_password = 'passw0rd'

    return (snmp_user, snmp_user_index, snmp_auth_password, snmp_priv_password)


class BrocadeException(Exception):

    def __init__(self, error_code, error_message=None):
        """
        error_code - int value, the error code of exception
                     1 - connection failed
                     2 - authentication error
                     3 - not switch
                     4 - unexpected result
        """
        self.error_code = error_code
        if error_message:
            self.error_message = error_message
        else:
            self.error_message = ''

    def __str__(self):
        return repr(self.error_code, self.error_message)


def update_snmp_v3_conf(engine_id, snmp_user, auth_protocol, auth_pass, priv_protocol, priv_pass, action_type, snmptrap_auth="log,execute,net", conf_file=SNMP_CONF_DEFAULT_POSITION + "/" + SNMPTRAPD_CONF_FILE):
    """
    the function is to update snmp setting in snmptrapd.conf

    action_type : 1 -- create/update
                  2 -- delete
    """
    _METHOD_ = "update_snmp_v3_conf"

    logging.info("ENTRY %s::params: endgineid = %s,snmp_user = %s, action_type = %s, config file = %s",
                 _METHOD_, engine_id, snmp_user, action_type, conf_file)
    read_file = open(conf_file, "r")
    try:
        contents = read_file.readlines()
    except Exception as e:
        logging.exception("CRITICAL %s::reading snmptrapd failed", _METHOD_, e)
        return 1
    finally:
        read_file.close()

    write_file = open(conf_file, "w")
    try:
        create_cmd_updated = False
        user_auth_updated = False
        create_user_cmd = " ".join(
            ["createUser", "-e", engine_id, snmp_user, auth_protocol, auth_pass, priv_protocol, priv_pass]) + "\n"
        user_auth_cmd = " ".join(
            ["authuser", "log,execute,net", snmp_user]) + "\n"
        user_auth_share = False
        for line in contents:
            # the engine_id should be unique
            if engine_id in line:
                if action_type == 2:
                    continue
                elif action_type == 1:
                    write_file.write(create_user_cmd)
                    create_cmd_updated = True
            # if other snmp client also use the same user, we should keep it
            elif engine_id not in line and re.match("^createUser.+\s" + snmp_user + "\s.+$", line) != None:
                user_auth_share = True
                write_file.write(line)
            # for user auth we can't use the XX in XX because user1 may be part
            # of user2 for example "pure" and "puremgr"
            elif user_auth_cmd == line:
                # as the line seq is unclear and may appear before the share define, so just delete it
                # and write it back if it's shared
                if action_type == 2:
                    continue
                elif action_type == 1:
                    write_file.write(user_auth_cmd)
                    user_auth_updated = True
            else:
                write_file.write(line)
        if action_type == 1:
            if not create_cmd_updated:
                write_file.write(create_user_cmd)
            if not user_auth_updated:
                write_file.write(user_auth_cmd)
        if action_type == 2 and user_auth_share == True:
            write_file.write(user_auth_cmd)
    except Exception as e:
        logging.exception("CRITICAL %s::edit snmptrapd failed", _METHOD_, e)
        return 1
    finally:
        write_file.close()

    logging.info("EXIT %s::update snmptrapd succeeded", _METHOD_)
    return 0
