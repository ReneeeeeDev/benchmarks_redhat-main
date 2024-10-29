from classes.compliance_check import ComplianceCheck


class DisableUSBStorageCheck(ComplianceCheck):
    TITLE = "Disable USB Storage"
    NUMBER = "1.1.10"
    COMMAND = [
        "modprobe -n -v usb-storage",
        "lsmod | grep usb-storage"
    ]
    PROFILE = ["Level 1 - Server", "Level 2 - Workstation"]
    DESCRIPTION = """
    USB storage provides a means to transfer and store files ensuring persistence and availability of the files independent 
    of network connection status. Its popularity and utility has led to USB-based malware being a simple and common means 
    for network infiltration and a first step to establishing a persistent threat within a networked environment.
    Restricting USB access on the system will decrease the physical attack surface for a device and diminish the possible 
    vectors to introduce malware.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMAND, self.PROFILE, self.DESCRIPTION)

    def check(self):
        # 1. Verify the modprobe command output
        modprobe_output = self.run_command(self.COMMAND[0])
        if 'install /bin/true' not in modprobe_output:
            return False

        # 2. Verify the module is not currently loaded
        lsmod_output = self.run_command(self.COMMAND[1])
        if lsmod_output != '':
            return False

        # If all checks pass, mark as passed
        self.passed = True
        return True
