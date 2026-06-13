"""
Various Unit Tests for the collector tool
"""

import unittest
import logger
from collector import parse_ssh_rlogin
from collector import parse_ssh_passauth
from collector import calculate_risk
from collector import SecurityChecks
from collector import Service
from collector import ServiceChecks
from collector import Filesystem
from collector import StorageInfo
from collector import ServerReport
    
CMD_SSHD_CFG1 = "cat tests/sample_ssh_1 | grep PermitRootLogin"
CMD_SSHD_PASS1 = "cat tests/sample_ssh_1 | grep PasswordAuthentication"
CMD_SSHD_CFG2 = "cat tests/sample_ssh_2 | grep PermitRootLogin"
CMD_SSHD_PASS2 = "cat tests/sample_ssh_2 | grep PasswordAuthentication"
CMD_SSHD_CFG3 = "cat tests/sample_ssh_3 | grep PermitRootLogin"
CMD_SSHD_PASS3 = "cat tests/sample_ssh_3 | grep PasswordAuthentication"
    
class TestSSHParsing(unittest.TestCase):

    def setUp(self):
        """
        No setup needed here
        """
        logger.info("Running SSH Parser Tests")
        pass

    def test_parse_rlogin_yes(self):
        """
        Tests that the PermitRootLogin value is set to yes
        """
        ret = parse_ssh_rlogin(CMD_SSHD_CFG1)
        self.assertEqual(ret, 'yes')

    def test_parse_rlogin_commented(self):
        """
        Tests that the PermitRootLogin value is commented
        so the assumed default is returned
        """
        ret = parse_ssh_rlogin(CMD_SSHD_CFG2)
        self.assertEqual(ret, 'prohibit-password')
        
    def test_parse_rlogin_no_value(self):
        """
        Tests that the PermitRootLogin value is missing
        so the assumed default is returned
        """
        ret = parse_ssh_rlogin(CMD_SSHD_CFG3)
        self.assertEqual(ret, 'prohibit-password')

    def test_parse_passauth_no(self):
        """
        Tests that the PasswordAuthentication value is set to no
        """
        ret = parse_ssh_passauth(CMD_SSHD_PASS1)
        self.assertEqual(ret, 'no')

    def test_parse_passauth_commented(self):
        """
        Tests that the PasswordAuthentication value is commented
        so the assumed default is returned
        """
        ret = parse_ssh_passauth(CMD_SSHD_PASS2)
        self.assertEqual(ret, 'yes')

    def test_parse_rlogin_no_value(self):
        """
        Tests that the PasswordAuthentication value is missing
        so the assumed default is returned
        """
        ret = parse_ssh_passauth(CMD_SSHD_PASS3)
        self.assertEqual(ret, 'yes')
    
class TestRiskScoreCalc(unittest.TestCase):

    def setUp(self):
        logger.info("Running Risk Score Calculator Tests")
        sec_checks = SecurityChecks(["user1","user2"],"yes","yes")
        service_checks = ServiceChecks("active",
            [Service("cron.service","failed","failed","failed"),
            Service("vbox.service","failed","failed","failed")])
        stor_info = StorageInfo([Filesystem("/dev/fs1","50%",False)])
        self.report = ServerReport(0,None,sec_checks,stor_info,service_checks,None)

    def test_risk_score_85(self):
        score = calculate_risk(self.report)
        self.assertEqual(score, 85)

    def test_risk_score_100(self):
        self.report.storage_info.filesystems[0].over_threshold = True
        score = calculate_risk(self.report)
        self.assertEqual(score, 100)

if __name__ == '__main__':
    unittest.main()
    