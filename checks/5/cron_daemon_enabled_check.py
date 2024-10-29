from classes.compliance_check import ComplianceCheck

class CronDaemonEnabledCheck(ComplianceCheck):
    TITLE = "Ensure cron daemon is enabled"
    NUMBER = "5.1.1"
    COMMANDS = [
        'systemctl is-enabled crond'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """The cron daemon is used to execute batch jobs on the system.
    While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and cron is used to execute them."""

    def __init__(self):
        super().__init__(CronDaemonEnabledCheck.TITLE, CronDaemonEnabledCheck.NUMBER, CronDaemonEnabledCheck.COMMANDS,
                         CronDaemonEnabledCheck.PROFILE, CronDaemonEnabledCheck.DESCRIPTION)

    def check(self):
        # Verify cron daemon is enabled
        cron_status = self.run_command(self.COMMANDS[0])
        if 'enabled' in cron_status:
            self.passed = True
        else:
            self.passed = False
        return self.passed
