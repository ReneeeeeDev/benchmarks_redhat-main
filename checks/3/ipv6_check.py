from classes.compliance_check import ComplianceCheck

class IPv6Check(ComplianceCheck):
    TITLE = "Verify if IPv6 is enabled on the system"
    NUMBER = "3.1.1"
    COMMANDS = [
              r'''#!/usr/bin/env bash
                check_ipv6() {
                output=""
                grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
                searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"
                if [ -s "$grubfile" ]; then
                ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && output="IPv6 Disabled in \"$grubfile\""
                fi
                if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $searchloc && \
                grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $searchloc && \
                sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
                sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
                [ -n "$output" ] && output="$output, and in sysctl config" || output="ipv6 disabled in sysctl config"
                fi
                [ -n "$output" ] && echo -e "\n$output\n" || echo -e "\nIPv6 is enabled on the system\n"
                }
                check_ipv6'''
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """Internet Protocol Version 6 (IPv6) is the most recent version of Internet Protocol (IP). 
    It's designed to supply IP addressing and additional security to support the predicted growth of connected devices.
    It is recommended that either IPv6 settings are configured OR IPv6 be disabled to reduce the attack surface of the system.
    IETF RFC 4038 recommends that applications are built with an assumption of dual stack.
    If IPv6 is disabled through sysctl config, SSH X11forwarding may no longer function as expected. We recommend that SSH X11forwarding be disabled, 
    but if required, the following will allow for SSH X11forwarding with IPv6 disabled through sysctl config:
    Add the following line the /etc/ssh/sshd_config file: AddressFamily inet
    Run the following command to re-start the openSSH server: # systemctl restart sshd"""

    def __init__(self):
        super().__init__(IPv6Check.TITLE, IPv6Check.NUMBER, IPv6Check.COMMANDS,
                         IPv6Check.PROFILE, IPv6Check.DESCRIPTION)

    def check(self):
        # As this is a manual check, we simply return False to indicate that it requires manual verification
        self.passed = False
        return self.passed
