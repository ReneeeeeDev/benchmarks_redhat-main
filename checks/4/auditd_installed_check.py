from classes.compliance_check import ComplianceCheck


class AuditdInstalledCheck(ComplianceCheck):
    TITLE = "Ensure auditd is installed"
    NUMBER = "4.1.1.1"
    COMMANDS = [
        'rpm -q audit'
    ]
    PROFILE = ["Level 2 - Server", "Level 2 - Workstation"]
    DESCRIPTION = """auditd is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk.
    The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring."""

    def __init__(self):
        super().__init__(AuditdInstalledCheck.TITLE, AuditdInstalledCheck.NUMBER, AuditdInstalledCheck.COMMANDS,
                         AuditdInstalledCheck.PROFILE, AuditdInstalledCheck.DESCRIPTION)

    def check(self):
        # Verify auditd is installed
        auditd_output = self.run_command(self.COMMANDS[0])
        if 'audit' in auditd_output:
            self.passed = True
        else:
            self.passed = False
        return self.passed
