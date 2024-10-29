from classes.compliance_check import ComplianceCheck

class RootPathIntegrityCheck(ComplianceCheck):
    TITLE = "Ensure root PATH Integrity"
    NUMBER = "6.2.7"
    COMMANDS = [
        '''RPCV="$(sudo -Hiu root env | grep '^PATH=' | cut -d= -f2)"
        echo "$RPCV" | grep -q "::" && echo "root's path contains an empty directory (::)"
        echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
        for x in $(echo "$RPCV" | tr ":" " "); do
            if [ -d "$x" ]; then
                ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"}
                $3 != "root" {print $9, "is not owned by root"}
                substr($1,6,1) != "-" {print $9, "is group writable"}
                substr($1,9,1) != "-" {print $9, "is world writable"}'
            else
                echo "$x is not a directory"
            fi
        done'''
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    The root user can execute any command on the system and could be fooled into executing programs unintentionally if the PATH is not set correctly.
    Including the current working directory (.) or other writable directory in root's executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMANDS, self.PROFILE, self.DESCRIPTION)

    def check(self):
        command_output = self.run_command(self.COMMANDS[0])
        if command_output:
            # If there is any output, it means there are issues with the root PATH
            self.passed = False
            return False

        # If no output, it means the root PATH is correctly set
        self.passed = True
        return True
