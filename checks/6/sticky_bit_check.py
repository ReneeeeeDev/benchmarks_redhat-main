from classes.compliance_check import ComplianceCheck

class StickyBitCheck(ComplianceCheck):
    TITLE = "Ensure sticky bit is set on all world-writable directories"
    NUMBER = "6.1.2"
    COMMANDS = [
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null"
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.
    This feature prevents the ability to delete or rename files in world writable directories (such as /tmp) that are owned by another user."""

    def __init__(self):
        super().__init__(StickyBitCheck.TITLE, StickyBitCheck.NUMBER, StickyBitCheck.COMMANDS,
                         StickyBitCheck.PROFILE, StickyBitCheck.DESCRIPTION)

    def check(self):
        # Verify no world writable directories exist without the sticky bit set
        sticky_bit_output = self.run_command(self.COMMANDS[0])
        if sticky_bit_output == '':
            self.passed = True
        else:
            self.passed = False
        return self.passed
