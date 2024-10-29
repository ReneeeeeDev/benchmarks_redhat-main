from classes.compliance_check import ComplianceCheck


class SquashfsCheck(ComplianceCheck):
    TITLE = "Ensure mounting of squashfs filesystems is disabled"
    NUMBER = "1.1.1.2"
    COMMANDS = [
        'modprobe -n -v squashfs | grep "^install"',
        'lsmod | grep squashfs',
        'grep -E "^blacklist\\s+squashfs" /etc/modprobe.d/*'
    ]
    PROFILE = ["Level 2 - Server", "Level 2 - Workstation"]
    DESCRIPTION = """The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small 
    footprint systems. A squashfs image can be used without having to first decompress it. 
    Removing support for unneeded filesystem types reduces the local attack surface of the system. 
    If this filesystem type is not needed, disable it.
    Impact: As Snap packages utilizes squashfs as a compressed filesystem, disabling squashfs will cause Snap packages to fail. 
    Snap application packages of software are self-contained and work across a range of Linux distributions. 
    This is unlike traditional Linux package management approaches, like APT or RPM, which require specifically adapted 
    packages per Linux distribution on an application update and delay therefore application deployment from developers 
    to their software's end-user. Snaps themselves have no dependency on any external store ("App store"), can be obtained 
    from any source and can be therefore used for upstream software deployment."""

    def __init__(self):
        super().__init__(SquashfsCheck.TITLE, SquashfsCheck.NUMBER, SquashfsCheck.COMMANDS,
                         SquashfsCheck.PROFILE, SquashfsCheck.DESCRIPTION)

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
        if 'blacklist squashfs' not in blacklist_output:
            return False

        # If all checks pass, mark as passed
        self.passed = True
        return True
