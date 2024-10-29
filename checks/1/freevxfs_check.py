import subprocess
from classes.compliance_check import ComplianceCheck


class FreevxfsCheck(ComplianceCheck):
    TITLE = "Ensure mounting of freevxfs filesystems is disabled"
    NUMBER = "1.1.1.2"
    COMMANDS = [
        'modprobe -n -v freevxfs | grep "^install"',
        'lsmod | grep freevxfs',
        'grep -E "^blacklist\\s+freevxfs" /lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the 
primary filesystem type for HP-UX operating systems."""

    def __init__(self):
        super().__init__(FreevxfsCheck.TITLE, FreevxfsCheck.NUMBER, FreevxfsCheck.COMMANDS,
                         FreevxfsCheck.PROFILE, FreevxfsCheck.DESCRIPTION)
        self.output_pass = []
        self.output_fail = []

    def run_command(self, command):
        try:
            result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return ""

    def module_loadable_chk(self):
        loadable = self.run_command(self.COMMANDS[0])
        if 'install /bin/false' in loadable or 'install /bin/true' in loadable:
            self.output_pass.append(f"- module: 'freevxfs' is not loadable: '{loadable}'")
        else:
            self.output_fail.append(f"- module: 'freevxfs' is loadable: '{loadable}'")

    def module_loaded_chk(self):
        loaded = self.run_command(self.COMMANDS[1])
        if loaded == '':
            self.output_pass.append("- module: 'freevxfs' is not loaded")
        else:
            self.output_fail.append(f"- module: 'freevxfs' is loaded: '{loaded}'")

    def module_deny_chk(self):
        blacklist = self.run_command(self.COMMANDS[2])
        if 'blacklist freevxfs' in blacklist:
            self.output_pass.append("- module: 'freevxfs' is deny listed")
        else:
            self.output_fail.append("- module: 'freevxfs' is not deny listed")

    def check(self):
        # Run checks
        self.module_loadable_chk()
        self.module_loaded_chk()
        self.module_deny_chk()

        # Display results
        if not self.output_fail:
            print("\n- Audit Result:\n ** PASS **\n", "\n".join(self.output_pass))
            self.passed = True
        else:
            print("\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n", "\n".join(self.output_fail))
            if self.output_pass:
                print("\n- Correctly set:\n", "\n".join(self.output_pass))
            self.passed = False

        return self.passed
#1.1.1.2