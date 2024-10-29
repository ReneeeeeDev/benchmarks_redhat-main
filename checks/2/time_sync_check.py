from classes.compliance_check import ComplianceCheck


class TimeSyncCheck(ComplianceCheck):
    TITLE = "Ensure time synchronization is in use"
    NUMBER = "2.1.1"
    COMMANDS = [
        'rpm -q chrony'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """System time should be synchronized between all systems in an environment. 
    This is typically done by establishing an authoritative time server or set of servers and having all systems 
    synchronize their clocks to them. Note: If another method for time synchronization is being used, this section may be skipped.
    Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files 
    have consistent time records across the enterprise, which aids in forensic investigations."""

    def __init__(self):
        super().__init__(TimeSyncCheck.TITLE, TimeSyncCheck.NUMBER, TimeSyncCheck.COMMANDS,
                         TimeSyncCheck.PROFILE, TimeSyncCheck.DESCRIPTION)

    def check(self):
        # Verify chrony is installed
        chrony_output = self.run_command(self.COMMANDS[0])
        if 'chrony' in chrony_output:
            self.passed = True
        else:
            self.passed = False
        return self.passed
