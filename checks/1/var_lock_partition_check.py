from classes.compliance_check import ComplianceCheck


class VarLogPartitionCheck(ComplianceCheck):
    TITLE = "Ensure separate partition exists for /var/log"
    NUMBER = "1.1.5.1"
    COMMANDS = [
        'findmnt --kernel /var/log'
    ]
    PROFILE = ["Level 2 - Server", "Level 2 - Workstation"]
    DESCRIPTION = """
    The /var/log directory is used by system services to store log data.
    The reasoning for mounting /var/log on a separate partition is as follow.
    Protection from resource exhaustion
    The default installation only creates a single / partition. Since the /var directory may contain world-writable files 
    and directories, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up 
    and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to /var 
    and cause unintended behavior across the system as the disk is full. See man auditd.conf for details.
    Fine grained control over the mount
    Configuring /var as its own file system allows an administrator to set additional mount options such as noexec/nosuid/nodev. 
    These options limit an attacker’s ability to create exploits on the system. Other options allow for specific behavior. 
    See man mount for exact details regarding filesystem-independent and filesystem-specific options.
    Protection from exploitation
    An example of exploiting /var may be an attacker establishing a hard-link to a system setuid program and wait for it to be updated. 
    Once the program was updated, the hard-link would be broken and the attacker would have his own copy of the program. 
    If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.
    Impact:
    Resizing filesystems is a common activity in cloud-hosted servers. Separate filesystem partitions may prevent successful resizing, 
    or may require the installation of additional tools solely for the purpose of resizing operations. 
    The use of these additional tools may introduce their own security considerations.
    """

    def __init__(self):
        super().__init__(VarLogPartitionCheck.TITLE, VarLogPartitionCheck.NUMBER, VarLogPartitionCheck.COMMANDS,
                         VarLogPartitionCheck.PROFILE, VarLogPartitionCheck.DESCRIPTION)

    def check(self):
        # Verify /var/log is mounted
        findmnt_output = self.run_command(self.COMMANDS[0])
        if '/var/log' not in findmnt_output:
            return False

        # If check passes, mark as passed
        self.passed = True
        return True
