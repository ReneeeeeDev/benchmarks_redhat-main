from classes.compliance_check import ComplianceCheck

class LogrotateCheck(ComplianceCheck):
    TITLE = "Ensure logrotate is configured"
    NUMBER = "4.3"
    COMMANDS = [
        'ls /etc/logrotate.conf',
        'ls /etc/logrotate.d/',
        'cat /etc/logrotate.conf',
        'cat /etc/logrotate.d/*'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    The system includes the capability of rotating log files regularly to avoid filling up the system with logs or 
    making the logs unmanageably large. The file /etc/logrotate.d/syslog is the configuration file used to rotate 
    log files created by syslog or rsyslog.
    By keeping the log files smaller and more manageable, a system administrator can easily archive these files to 
    another system and spend less time looking through inordinately large log files.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMANDS, self.PROFILE, self.DESCRIPTION)

    def check(self):
        # Verify that /etc/logrotate.conf exists
        logrotate_conf_exists = self.run_command(self.COMMANDS[0])
        if not logrotate_conf_exists:
            return False

        # Verify that /etc/logrotate.d/ exists and is not empty
        logrotate_d_exists = self.run_command(self.COMMANDS[1])
        if not logrotate_d_exists:
            return False

        # Review /etc/logrotate.conf
        logrotate_conf_content = self.run_command(self.COMMANDS[2])
        if not logrotate_conf_content:
            return False

        # Review /etc/logrotate.d/* files
        logrotate_d_content = self.run_command(self.COMMANDS[3])
        if not logrotate_d_content:
            return False

        self.passed = True
        return True
