"""
This is the main script of the application expected to be scheduled as a cron job.
it will collect a predetermined set of system data, calculate a Risk Score and send 
a report to a server.
"""

# This file contains all the hardcoded for now values including API url, Server IP
# and the various command strings

import os
import json
import re
from datetime import datetime
from subprocess import Popen, PIPE
from dataclasses import dataclass, asdict
import requests

import settings
import logger

VALID_SSHPERM = re.compile(r'^#{0,1}PermitRootLogin (.*)$')
VALID_SSHPASS = re.compile(r'^#{0,1}PasswordAuthentication (.*)$')
VALID_ROUTE = re.compile(r'^default *(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*$')

@dataclass
class SystemInfo:
    """
    Contains various general System information for the server
    """
    hostname: str
    operating_system: str
    kernel_version: str
    uptime: str

@dataclass
class SecurityChecks:
    """
    Contains various general System security checks for the server
    """
    uid0_users: list[str]
    ssh_root_login: str
    ssh_password_authentication: str

@dataclass
class Filesystem:
    """
    This represents some basic information necessary for each FS
    """
    name: str
    utilization: str
    over_threshold: bool

@dataclass
class StorageInfo:
    """
    Contains various general Storage information for the server
    """
    filesystems: list[Filesystem]

@dataclass
class Service:
    """
    This represents some basic systemd service information
    """
    unit: str
    load: str
    active: str
    sub: str

@dataclass
class ServiceChecks:
    """
    Contains various general System Service checks for the server
    """
    ssh_service_status: str
    failed_services: list[Service]

@dataclass
class TCPPort:
    """
    This represents some basic tcp port information
    """
    proto: str
    local: str
    foreign: str
    state: str

@dataclass
class NetworkChecks:
    """
    Contains various general Network checks for the server
    """
    default_route: str
    tcp_listening_ports: list[TCPPort]

@dataclass
class ServerReport:
    """
    This is the complete Server status report that also includes
    the Risk Score
    """
    risk_score: int
    system_info: SystemInfo
    security_checks: SecurityChecks
    storage_info: StorageInfo
    service_checks: ServiceChecks
    network_checks: NetworkChecks

def transmit(server, api, report):
    """
    The transmit function will POST the collated report to the url indicated
    in the settings file
    
    Args:
        server(str): The Target Collector Server url
        api(str): The Target Collecting API path
        report(dict): The JSON that contains the report
    """
    TARGET_URL = server+api
    if len(report) > 0:
        r = None
        try:
            r = requests.post(TARGET_URL, json=report, timeout=settings.REQUEST_TIMEOUT)
        except Exception as err:
            logger.logException(err)
            logger.error(f"NO REPLY from {TARGET_URL}")

        if r is not None and r.status_code >= 400:
            logger.error(f"Received error code while posting report: {str(r.status_code)}")
        elif r is not None:
            logger.info("Report posted succesfully")

def get_info(command, sudo=False):
    """
    Execute a command via subprocess
    
    Args:
        command(str): The command to be executed
        sudo(bool): If the command needs to be executed as sudo.
                    NOTE: Will only work if the script was run with
                    root priviledges or you interactively supply them   
    """
    ret_str = "N/A"
    try:
        if sudo:
            command = "sudo " + command
        with Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                text=True) as process:
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                ret_str = stdout
            else:
                logger.error(stderr)
    except Exception as err:
        logger.logException(err)
    return ret_str.strip()

def collect():
    """
    The main collector function. Will populate the info dataclasses
    assemble the report JSON and call the transmit function.
    """
    logger.info("Starting System Data collection")
    # System Info
    hostname_str = get_info(settings.CMD_HOSTNAME)
    os_str = get_info(settings.CMD_OS)
    kernel_str = get_info(settings.CMD_KERNEL)
    # Not clear if we need to just isolate the "up" value here so we
    # supply all of it
    upt_str = get_info(settings.CMD_UPTIME)

    system_info = SystemInfo(hostname_str,os_str,kernel_str,upt_str)
    # print(json.dumps(asdict(system_info)))

    # Security Checks
    uidz_users = []
    users_str = get_info(settings.CMD_USERS)
    if len(users_str) > 3:
        lines = users_str.split(settings.NEWLINE)
        for l in lines:
            parts = l.split(settings.USR_DELIM)
            if len(parts) > 3:
                try:
                    uid = int(parts[2])
                    if uid == 0:
                        uidz_users.append(f"user: {parts[0]} GID:{parts[3]}")
                except Exception as err:
                    logger.logException(err)

    # Assume prohibit-password default if we cannot parse a line?
    # We also assume no per user settings!
    ssh_rlogin_value = "prohibit-password"
    ssh_rlogin_str = get_info(settings.CMD_SSHD_CFG)
    if len(ssh_rlogin_str) > 0:
        lines = ssh_rlogin_str.split(settings.NEWLINE)
        for l in lines:
            m = VALID_SSHPERM.match(l)
            if m:
                if l[0] != "#":
                    ssh_rlogin_value = f"{m.group(1)}"

    # Assume yes default if we cannot parse a line?
    # We also assume no per user settings!
    ssh_passauth_value = "yes"
    ssh_passauth_str = get_info(settings.CMD_SSHD_PASS)
    if len(ssh_passauth_str) > 0:
        lines = ssh_passauth_str.split(settings.NEWLINE)
        for l in lines:
            m = VALID_SSHPASS.match(l)
            if m:
                if l[0] != "#":
                    ssh_passauth_value = f"{m.group(1)}"

    sec_checks = SecurityChecks(uidz_users,ssh_rlogin_value,ssh_passauth_value)
    # print(json.dumps(asdict(sec_checks)))

    # Storage Info
    # We assume local Filesystems only!
    fs_list = []
    filesystems_str = get_info(settings.CMD_DF)
    if len(filesystems_str) > 0:
        lines = filesystems_str.split(settings.NEWLINE)
        try:
            header = (lines[0]).strip()
            # Find the Utilization column
            name_col_idx = 0
            utl_col_idx = -1
            fields = header.split(" ")
            fields = [i for i in fields if len(i) > 0]
            for idx,value in enumerate(fields):
                if value.lower() in settings.DF_CAPACITY_STR:
                    utl_col_idx = idx
                    break
            if utl_col_idx == -1:
                logger.error("Could not parse index for Utilization column!")
            else:
                lines = lines[1:]
                for l in lines:
                    try:
                        parts = (l.strip()).split(" ")
                        parts = [i for i in parts if len(i) > 0]
                        util_prc = 0
                        util_str = (parts[utl_col_idx]).replace("%","")
                        util_prc = int(util_str)
                        fs = Filesystem(parts[name_col_idx],parts[utl_col_idx],
                            True if util_prc>settings.FS_THRESOLD else False)
                        fs_list.append(fs)
                    except Exception as err:
                        logger.logException(err)
        except Exception as err:
            logger.logException(err)

    storage_info = StorageInfo(fs_list)
    # print(json.dumps(asdict(storage_info)))

    failed_list = []
    filesystems_str = get_info(settings.CMD_SYSTEMD_FAILED)
    if len(filesystems_str) > 0:
        lines = filesystems_str.split(settings.NEWLINE)
        for l in lines:
            try:
                parts = (l.strip()).split(" ")
                parts = [i for i in parts if len(i) > 0]
                start_indx = 0
                while start_indx < len(parts) and ".service" not in parts[start_indx]:
                    start_indx+=1
                if start_indx < len(parts) and ".service" in parts[start_indx]:
                    failed_list.append(Service(parts[start_indx],
                        parts[start_indx+1],parts[start_indx+2],parts[start_indx+3]))
            except Exception as err:
                logger.logException(err)

    # We are assuming that if not in failed or active the status
    # is inactive
    ssh_status = "inactive"
    for fs in failed_list:
        if fs.unit == "ssh.service":
            ssh_status = "failed"
    if ssh_status != "failed":
        ssh_status_str = get_info(settings.CMD_SYSTEMD_SSH)
        if len(ssh_status_str) > 0 and ssh_status_str != "N/A":
            ssh_status = "active"
    service_info = ServiceChecks(ssh_status,failed_list)
    # print(json.dumps(asdict(service_info)))

    port_list = []
    tcpports_str = get_info(settings.CMD_NETSTAT_PORTS)
    if len(tcpports_str) > 0:
        lines = tcpports_str.split(settings.NEWLINE)
        for l in lines:
            try:
                parts = (l.strip()).split(" ")
                parts = [i for i in parts if len(i) > 0]
                if "tcp" in parts[0]:
                    p = TCPPort(parts[0],parts[3],parts[4],parts[5])
                    port_list.append(p)
            except Exception as err:
                logger.logException(err)

    default_route = "N/A"
    default_route_str = get_info(settings.CMD_DEF_ROUTE)
    if len(default_route_str) > 0:
        lines = default_route_str.split(settings.NEWLINE)
        for l in lines:
            m = VALID_ROUTE.match(l)
            if m:
                parts = (l.strip()).split(" ")
                parts = [i for i in parts if len(i) > 0]
                default_route = " ".join(parts)
                break

    net_info = NetworkChecks(default_route,port_list)
    # print(json.dumps(asdict(net_info)))

    # Calculate Risk Score
    risk_score = 0
    if ssh_rlogin_value.lower() == "yes":
        risk_score+=25
    if ssh_passauth_value.lower() == "yes":
        risk_score+=25
    if len(uidz_users) > 1:
        risk_score+=25
    for fs in fs_list:
        if fs.over_threshold is True:
            risk_score+=15
            break
    if len(failed_list) > 0:
        risk_score+=10

    report = ServerReport(risk_score,system_info,sec_checks,
        storage_info,service_info,net_info)
    report_dict = asdict(report)
    cache_report(json.dumps(report_dict, indent=4))
    logger.info("System Data collection Complete. Transmitting...")
    transmit(settings.REPORT_SERVER, settings.REPORT_API, report_dict)


def cache_report(report):
    """
    This will cache the generated report on a local folder
    
    Args:
        report(str): The report body
    """
    if len(report) > 0:
        filename = f"report_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}.json"
        full_path = os.path.join(settings.REPORTS_FOLDER,filename)
        logger.info(f"Caching report to {full_path}")
        with open(full_path,"w") as f:
            f.write(report)

if __name__ == "__main__":
    collect()
