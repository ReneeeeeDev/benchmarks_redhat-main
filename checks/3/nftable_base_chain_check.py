from classes.compliance_check import ComplianceCheck


class NftablesBaseChainsCheck(ComplianceCheck):
    TITLE = "Ensure nftables base chains exist"
    NUMBER = "3.4.2.6"
    COMMANDS = [
        'nft list ruleset | grep \'hook input\'',
        'nft list ruleset | grep \'hook forward\'',
        'nft list ruleset | grep \'hook output\''
    ]
    PROFILE = ["Level 1 - Server", "Level 1 - Workstation"]
    DESCRIPTION = """
    Chains are containers for rules. They exist in two kinds, base chains and regular chains. A base chain is an entry point for packets from the networking stack, a regular chain may be used as a jump target and is used for better rule organization.
    If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through those chains will not be touched by nftables.
    If configuring nftables over ssh, creating a base chain with a policy of drop will cause loss of connectivity.
    Ensure that a rule allowing ssh has been added to the base chain prior to setting the base chain's policy to drop.
    """

    def __init__(self):
        super().__init__(self.TITLE, self.NUMBER, self.COMMANDS, self.PROFILE, self.DESCRIPTION)

    def check(self):
        # Verify base chains exist for INPUT, FORWARD, and OUTPUT
        input_output = self.run_command(self.COMMANDS[0])
        forward_output = self.run_command(self.COMMANDS[1])
        output_output = self.run_command(self.COMMANDS[2])

        if 'hook input' in input_output and 'hook forward' in forward_output and 'hook output' in output_output:
            self.passed = True
            return True

        self.passed = False
        return False
