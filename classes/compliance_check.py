import subprocess

class ComplianceCheck:
    def __init__(self, title, number, command, profile, description):
        self.title = title
        self.number = number
        self.command = command
        self.profile = profile
        self.description = description
        self.passed = False

    def run_command(self, command=None):
        """
        Run the provided shell command and return the output.
        """
        if command is None:
            command = self.command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()

    def check(self):
        """
        Method to be overridden in derived classes to perform specific compliance checks.
        """
        raise NotImplementedError("Subclasses should implement this method.")
