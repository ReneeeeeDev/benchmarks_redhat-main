from classes.compliance_check import ComplianceCheck

class IMAPPOP3ServerCheck(ComplianceCheck):
    TITLE = "Ensure IMAP and POP3 server is not installed"
    NUMBER = "2.2.11"
    COMMANDS = [
        "rpm -q dovecot cyrus-imapd"
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    dovecot is an open source IMAP and POP3 server for Linux based systems.
    Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface.
    Note: Several IMAP/POP3 servers exist and can use other service names. These should also be audited and the packages removed if not required.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMANDS, self.PROFILE, self.DESCRIPTION)

    def check(self):
        # Verify that dovecot and cyrus-imapd are not installed
        rpm_output = self.run_command(self.COMMANDS[0])
        if 'package dovecot is not installed' in rpm_output and 'package cyrus-imapd is not installed' in rpm_output:
            self.passed = True
            return True
        return False
