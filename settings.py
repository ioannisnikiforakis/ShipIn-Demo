"""
This module will include several, hardcoded for now, values for the collector module
"""

REPORT_SERVER = "http://192.168.1.5"
REPORT_API = "/api/v1/server-report"

USR_DELIM = ":"
NEWLINE = "\n"
FS_THRESOLD = 85
REPORTS_FOLDER = "reports"
REQUEST_TIMEOUT = 30

# Command strings. At some point these could be read from
# a proper configuration file perhaps created on install
# and tailored to different systems

# System Info
CMD_HOSTNAME = "hostname"
CMD_OS  = "uname -sv"
CMD_KERNEL = "uname -r"
CMD_UPTIME = "uptime"

# Security Checks
CMD_USERS = "cat /etc/passwd"
CMD_SSHD_CFG = "cat /etc/ssh/sshd_config | grep PermitRootLogin"
CMD_SSHD_PASS = "cat /etc/ssh/sshd_config | grep PasswordAuthentication"

# Storage Checks
DF_CAPACITY_STR = ["use%","capacity"] # Please keep these values lowercase!
CMD_DF = "df -lh"

# Service Checks
CMD_SYSTEMD_FAILED = "systemctl --failed | grep -i failed"
CMD_SYSTEMD_SSH = "systemctl list-units --state=active | grep -i ssh.service"
# We will avoid "sudo systemctl status ssh.service" for now to avoid sudoing...

# Network Checks
CMD_NETSTAT_PORTS = "netstat -tnl | grep tcp"
CMD_DEF_ROUTE = "netstat -rn | grep -i default"
