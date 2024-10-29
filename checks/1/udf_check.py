from classes.compliance_check import ComplianceCheck

class UdfCheck(ComplianceCheck):
    TITLE = "Ensure mounting of udf filesystems is disabled"
    NUMBER = "1.1.1.3"
    COMMANDS = [
        'modprobe -n -v udf | grep "^install"',
        'lsmod | grep udf',
        'grep -E "^blacklist\\s*udf" /etc/modprobe.d/*'
    ]
    PROFILE = ["Level 2 - Server", "Level 2 - Workstation"]
    DESCRIPTION = """The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. 
    This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary 
    to support writing DVDs and newer optical disc formats. 
    Removing support for unneeded filesystem types reduces the local attack surface of the system. 
    If this filesystem type is not needed, disable it. 
    Impact: Microsoft Azure requires the usage of udf. 
    udf should not be disabled on systems run on Microsoft Azure."""

    def __init__(self):
        super().__init__(UdfCheck.TITLE, UdfCheck.NUMBER, UdfCheck.COMMANDS,
                         UdfCheck.PROFILE, UdfCheck.DESCRIPTION)

    def check(self):
        # 1. Verify module loading behavior
        modprobe_output = self.run_command(self.COMMANDS[0])
        if 'install /bin/false' not in modprobe_output:
            return False

        # 2. Verify module is not currently loaded
        lsmod_output = self.run_command(self.COMMANDS[1])
        if lsmod_output != '':
            return False

        # 3. Verify module is blacklisted
        blacklist_output = self.run_command(self.COMMANDS[2])
        if 'blacklist udf' not in blacklist_output:
            return False

        # If all checks pass, mark as passed
        self.passed = True
        return True
