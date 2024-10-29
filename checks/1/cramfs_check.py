from classes.compliance_check import ComplianceCheck


class CramfsCheck(ComplianceCheck):
    TITLE = "Ensure mounting of cramfs filesystems is disabled"
    NUMBER = "1.1.1.1"
    COMMANDS = [
        'modprobe -n -v cramfs | grep "^install"',
        'lsmod | grep cramfs',
        'grep -E "^blacklist\\s+cramfs" /etc/modprobe.d/*'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    Description = """The cramfs filesystem type is a compressed read - only Linux filesystem embedded in small
    footprint systems.A cramfs image can be used  without having to first decompress it. This can be used to mount  the
    image."""

    def __init__(self):
        super().__init__(CramfsCheck.TITLE,CramfsCheck.NUMBER,CramfsCheck.COMMANDS,
                         CramfsCheck.PROFILE, CramfsCheck.Description)



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
        if 'blacklist cramfs' not in blacklist_output:
            return False

        # If all checks pass, mark as passed
        self.passed = True
        return True
