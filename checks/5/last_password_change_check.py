from classes.compliance_check import ComplianceCheck

class LastPasswordChangeCheck(ComplianceCheck):
    TITLE = "Ensure all users last password change date is in the past"
    NUMBER = "5.6.1.5"
    COMMANDS = [
        'awk -F: \'/^[^:]+:[^!*]/{print $1}\' /etc/shadow | while read -r usr; do change=$(date -d "$(chage --list $usr | grep \'^Last password change\' | cut -d: -f2 | grep -v \'never$\')" +%s); if [[ "$change" -gt "$(date +%s)" ]]; then echo "User: \"$usr\" last password change was \"$(chage --list $usr | grep \'^Last password change\' | cut -d: -f2)\""; fi; done'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    All users should have a password change date in the past.
    If a users recorded password change date is in the future then they could bypass any set password expiration.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMANDS, self.PROFILE, self.DESCRIPTION)

    def check(self):
        command_output = self.run_command(self.COMMANDS[0])
        if command_output:
            # If there is any output, it means there are users with last password change dates in the future
            self.passed = False
            return False

        # If no output, it means all users' last password change dates are in the past
        self.passed = True
        return True
