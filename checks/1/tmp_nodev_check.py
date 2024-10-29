from classes.compliance_check import ComplianceCheck

class TmpNodevCheck(ComplianceCheck):
    TITLE = "Ensure nodev option set on /tmp partition"
    NUMBER = "1.1.2.2"
    COMMANDS = [
        'findmnt --kernel /tmp | grep nodev'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """The nodev mount option specifies that the filesystem cannot contain special devices.
    Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot create 
    a block or character special devices in /tmp."""

    def __init__(self):
        super().__init__(TmpNodevCheck.TITLE, TmpNodevCheck.NUMBER, TmpNodevCheck.COMMANDS,
                         TmpNodevCheck.PROFILE, TmpNodevCheck.DESCRIPTION)

    def check(self):
        # Verify that the nodev option is set for /tmp mount
        findmnt_output = self.run_command(self.COMMANDS[0])
        if 'nodev' not in findmnt_output:
            return False

        # If the check passes, mark as passed
        self.passed = True
        return True
