from classes.compliance_check import ComplianceCheck

class HfsCheck(ComplianceCheck):
    TITLE = "Ensure hfs kernel module is not available (Automated)"
    NUMBER = "1.1.1.3"  # Asigna el número adecuado
    COMMANDS = [
        'modprobe -n -v hfs | grep "^install"',
        'lsmod | grep hfs',
        'grep -E "^blacklist\\s+hfs" /etc/modprobe.d/*'
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """The hfs filesystem type is an Apple Hierarchical File System, which is not commonly used on 
    most Linux systems. Removing support for unneeded filesystem types reduces the local attack surface of the system. 
    If this filesystem type is not needed, disable it."""

    def __init__(self):
        super().__init__(HfsCheck.TITLE, HfsCheck.NUMBER, HfsCheck.COMMANDS,
                         HfsCheck.PROFILE, HfsCheck.DESCRIPTION)

    def check(self):
        # 1. Verificar si el módulo no es cargable
        modprobe_output = self.run_command(self.COMMANDS[0])
        if 'install /bin/false' not in modprobe_output and 'install /bin/true' not in modprobe_output:
            print(f"FAIL: Module {self.module_name} is loadable")
            return False

        # 2. Verificar si el módulo está cargado actualmente
        lsmod_output = self.run_command(self.COMMANDS[1])
        if lsmod_output != '':
            print(f"FAIL: Module {self.module_name} is loaded")
            return False

        # 3. Verificar si el módulo está en la lista de denegación (blacklist)
        blacklist_output = self.run_command(self.COMMANDS[2])
        if 'blacklist hfs' not in blacklist_output:
            print(f"FAIL: Module {self.module_name} is not blacklisted")
            return False

        # Si todas las verificaciones pasan, marcar como aprobado
        self.passed = True
        print(f"PASS: Module {self.module_name} is disabled as required")
        return True

# Ejemplo de ejecución
check = HfsCheck()
check.check()
