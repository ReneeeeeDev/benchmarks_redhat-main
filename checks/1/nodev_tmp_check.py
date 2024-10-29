from classes.compliance_check import ComplianceCheck


class NodevTmpCheck(ComplianceCheck):
    TITLE = "Ensure nodev option set on /tmp partition"
    NUMBER = "1.1.2.2"
    COMMAND = [
        "findmnt --kernel /tmp | grep nodev"
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    The nodev mount option specifies that the filesystem cannot contain special devices.
    Since the /tmp filesystem is not intended to support devices, set this option to ensure 
    that users cannot create a block or character special devices in /tmp.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMAND, self.PROFILE, self.DESCRIPTION)

    def check(self):
        # Execute the command to verify nodev option is set
        findmnt_output = self.run_command(self.COMMAND[0])
        if 'nodev' not in findmnt_output:
            return False

        # If check passes
        self.passed = True
        return True
