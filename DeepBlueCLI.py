from subprocess import check_output


class DeepBlueCLI:
    '''Using DeepBlueCLI triaging'''
    def deepBlue(self):
        '''Using subprocess.check_output to start powershell.exe and run DeepBlue.ps1'''
        output = check_output(["powershell.exe", "C:\\Users\koenw\Desktop\School\Afstuderen\DeepBlueCLI\DeepBlueCLI\DeepBlue.ps1"])
        print(output)
        return output