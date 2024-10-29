from classes.compliance_check import ComplianceCheck


class AideCheck(ComplianceCheck):
    TITLE = "Ensure AIDE is installed"
    NUMBER = "1.3.1"
    COMMANDS = [
        'rpm -q aide'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    Advanced Intrusion Detection Environment (AIDE) is an intrusion detection tool that uses predefined rules to check 
    the integrity of files and directories in the Linux operating system. AIDE has its own database to check the 
    integrity of files and directories.
    AIDE takes a snapshot of files and directories including modification times, permissions, and file hashes which 
    can then be used to compare against the current state of the filesystem to detect modifications to the system.
    By monitoring the filesystem state, compromised files can be detected to prevent or limit the exposure of accidental 
    or malicious misconfigurations or modified binaries.
    """

    def __init__(self):
        super().__init__(AideCheck.TITLE, AideCheck.NUMBER, AideCheck.COMMANDS,
                         AideCheck.PROFILE, AideCheck.DESCRIPTION)

    def check(self):
        # Verify AIDE is installed
        rpm_output = self.run_command(self.COMMANDS[0])
        if 'aide' not in rpm_output:
            return False

        # If check passes, mark as passed
        self.passed = True
        return True
