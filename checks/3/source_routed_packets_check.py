from classes.compliance_check import ComplianceCheck

class SourceRoutedPacketsCheck(ComplianceCheck):
    TITLE = "Ensure source routed packets are not accepted"
    NUMBER = "3.3.1"
    COMMANDS = [
        'sysctl net.ipv4.conf.all.accept_source_route',
        'sysctl net.ipv4.conf.default.accept_source_route',
        'sysctl net.ipv6.conf.all.accept_source_route',
        'sysctl net.ipv6.conf.default.accept_source_route',
        r'grep -Psl -- "^\s*net\.ipv4\.conf\.all\.accept_source_route\s*=\s*0\b\s*(#.*)?$" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf',
        r'grep -Psl -- "^\s*net\.ipv4\.conf\.default\.accept_source_route\s*=\s*0\b\s*(#.*)?$" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf',
        r'grep -Psl -- "^\s*net\.ipv6\.conf\.all\.accept_source_route\s*=\s*0\b\s*(#.*)?$" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf',
        r'grep -Psl -- "^\s*net\.ipv6\.conf\.default\.accept_source_route\s*=\s*0\b\s*(#.*)?$" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr.lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    Setting net.ipv4.conf.all.accept_source_route, net.ipv4.conf.default.accept_source_route, 
    net.ipv6.conf.all.accept_source_route and net.ipv6.conf.default.accept_source_route to 0 
    disables the system from accepting source routed packets. This prevents an attacker from 
    using source routed packets to gain access to private address systems that are not 
    routable from the Internet routable addresses.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMANDS, self.PROFILE, self.DESCRIPTION)

    def check(self):
        # Verify sysctl settings for ipv4 and ipv6 source routed packets
        for command in self.COMMANDS[:4]:
            sysctl_output = self.run_command(command)
            if "0" not in sysctl_output:
                return False

        # Verify configuration files for ipv4 and ipv6 source routed packets
        for command in self.COMMANDS[4:]:
            grep_output = self.run_command(command)
            if not grep_output:
                return False

        self.passed = True
        return True
