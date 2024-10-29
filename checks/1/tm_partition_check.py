from classes.compliance_check import ComplianceCheck

class TmpPartitionCheck(ComplianceCheck):
    TITLE = "Ensure /tmp is a separate partition"
    NUMBER = "1.1.2.1"
    COMMANDS = [
        'findmnt --kernel /tmp',
        'systemctl is-enabled tmp.mount'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """The /tmp directory is a world-writable directory used for temporary storage by all users and some applications. 
    Making /tmp its own file system allows an administrator to set additional mount options such as the noexec option on the mount, 
    making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to 
    a system setuid program and wait for it to be updated. Once the program was updated, the hard link would be broken and the attacker 
    would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit 
    the known flaw. This can be accomplished by either mounting tmpfs to /tmp, or creating a separate partition for /tmp."""

    def __init__(self):
        super().__init__(TmpPartitionCheck.TITLE, TmpPartitionCheck.NUMBER, TmpPartitionCheck.COMMANDS,
                         TmpPartitionCheck.PROFILE, TmpPartitionCheck.DESCRIPTION)

    def check(self):
        # 1. Verify /tmp is mounted
        findmnt_output = self.run_command(self.COMMANDS[0])
        if '/tmp' not in findmnt_output:
            return False

        # 2. Verify systemd will mount the /tmp partition at boot time
        systemctl_output = self.run_command(self.COMMANDS[1])
        if 'enabled' not in systemctl_output and 'static' not in systemctl_output:
            return False

        # If all checks pass, mark as passed
        self.passed = True
        return True
