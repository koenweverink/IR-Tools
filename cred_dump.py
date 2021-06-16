import yara
import os, json, datetime
from pathlib import Path
from velociraptor.main import Velociraptor


class CredentialDump:
    '''Looking for traces of Credential Dumping by detecting Mimikatz using Yara Rules, and Velociraptor Impersonation.'''
    def __init__(self, path, map):
        '''
        :param path: str
        :param map: str
        '''
        super().__init__()

        self.rules = yara.compile(r'IR-Tools/mimikatz.yar')
        self.map = map
        self.path = path
        self.folder = 'credential_dump_results'
        
        self.v = Velociraptor()

        self.today = str(datetime.date.today())
        paths = os.path.join(self.path, self.folder)
        Path(paths).mkdir(parents=True, exist_ok=True)

        self.destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(self.folder)

    def callback_mimikatz(self, data):
        '''
        Serves as the callback for the get_matches method.
        :param data: dict
        :return: bool
        '''
        return yara.CALLBACK_CONTINUE


    def get_matches(self):
        '''Looking for the presence of Mimikatz using YARA rules.'''
        matches = {}
        for root, dirs, files in os.walk(self.map):
            for file in files:
                ftm = os.path.join(root, file)
                match = self.rules.match(ftm, callback=self.callback_mimikatz, which_callbacks=yara.CALLBACK_MATCHES)
                if match:
                    matches[ftm] = match
        
        for match in matches:
            with open(self.destination, 'a', encoding='utf-8') as f:
                json.dump(match, f, ensure_ascii=False, indent=4)
        
        return matches


    def detect_impersonation(self):
        '''Calling Velociraptor to check for an elevated impersonation token.'''
        query = """
        SELECT *
        FROM Artifacts.Windows.Detection.Impersonation() 
        WHERE ImpersonationToken.IsElevated = True         
        """
        filename = 'creddump_result'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)


if __name__ == "__main__":
    folder = 'C:\\Users\\koenw\\Desktop\\School\\Afstuderen\\IR-Tools\\mimikatz\\'
    map = 'C:\\Users\\koenw\\Desktop\\School\\Afstuderen\\IR-Tools\\mimikatz\\'
    r = CredentialDump(folder, map)
    print(help(r))
    