from Script_event_logs import ParseEventLogs
from Script_filesystem import ParseFilesystem
from Script_registry_files import ParseRegistry
from velociraptor.main import Velociraptor

from pathlib import Path

import json, os, datetime


class maliciousPowershell:
    ''' This script is used to collect all eventlogs that can indicate the malicious use of Powershell (Destination).'''
    def __init__(self, path):
        ''':param path: str'''
        super().__init__()

        '''Place all the variables here, whenever a separate collection has already been performed.'''
        self.SYSTEM_evtx = r'C:\Windows\System32\winevt\Logs\System.evtx'
        self.SYSTEM_reg = r'C:\Users\koenw\Desktop\School\Afstuderen\IR-Tools\Registries\SYSTEM'
        self.WinPowerShell_O = 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx'
        self.Prefetch = 'C:\Windows\Prefetch'
        self.path = path
        self.folder = 'powershell_results'

        self.malware = 'wsmprovhost.exe'
        self.overig = False

        self.p = ParseEventLogs(self.path, self.folder)
        self.f = ParseFilesystem(self.path, self.folder, self.malware, self.overig)
        self.r = ParseRegistry(self.path, self.folder, self.malware, self.overig)
        self.v = Velociraptor()

        self.today = str(datetime.date.today())
        paths = os.path.join(self.path, self.folder)
        Path(paths).mkdir(parents=True, exist_ok=True)


    def security_logs(self):
        '''Finds event log 4624 logon type 3, followed by 4672 admin login.'''
        query_seclog_4624="""
            SELECT System.EventID.Value AS EventID,
                    System.TimeCreated.SystemTime AS TimeCreated,
                    System.Computer AS Computer,
                    EventData.LogonType As LogonType
        
            FROM parse_evtx(filename='C:/Windows/System32/Winevt/Logs/Security.evtx') 
            WHERE System.EventID.Value = 4624 AND EventData.LogonType = 3
            """
    
        query_seclog_4672="""
            SELECT System.EventID.Value AS EventID,
                    System.TimeCreated.SystemTime AS TimeCreated,
                    System.Computer AS Computer,
                    EventData.LogonType As LogonType
        
            FROM parse_evtx(filename='C:/Windows/System32/Winevt/Logs/Security.evtx') 
            WHERE System.EventID.Value = 4672
            """
        
        self.v.query(query_seclog_4624)
        # 4688 A process was created; 4689 Process exited


    def powershell_operational_4104(self):
        '''Finds event log 4104: script block logging; can be configured to log all scripts, and outputs it to the selected folder.'''
        result, output_xml, output_csv = self.p.windows_powershell_4104(self.WinPowerShell_O)
        return result, output_xml, output_csv


    def powershell_operational_53504(self):
        '''Finds event log 53504: logs the authenticating user, and outputs it to the selected folder.'''
        result, output_xml, output_csv = self.p.windows_powershell_53504(self.WinPowerShell_O)
        return result, output_xml, output_csv


    def powershell(self):
        """UNDER DEVELOPMENT 
        Finds event log 400, 403 and 800: The start and end times of a remote session, 
        including partial script code, and outputs it to the selected folder."""
        # 400, 403:  start and end times of remoting session
        # 800: includes partial script code
        pass


    def WinRM_operational(self):
        """UNDER DEVELOPMENT
        Finds event log 91 (session creation) and 168 (authenticating user) in Microsoft-Windows-WinRM%4Operational.evtx."""
        # :
        # 91: session creation
        # 168: logs the authenticating user
        pass


    def system_reg(self):
        '''Looks in \CurrentControlSet\Control\Session Manager\AppCompatCache for wsmprovhost.exe and malicious.exe.'''
        self.r.AppCompatCache(self.SYSTEM_reg)
    

    def powershell_filesystem(self):
        '''Looks in C:\Windows\Prefetch for wsmprovhost.exe-<HASH>.pf and “malicious.exe”-<HASH>.pf.'''
        self.f.prefetch(self.Prefetch)


    def powershell_scriptblock(self):
        '''Calls Velociraptor to check for Powershell Scriptblocking.'''
        query = """
        SELECT *
        FROM Artifact.Windows.EventLogs.PowershellScriptblock()
        """
        filename = 'scriptblock_result'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)

    
    def powershell_persistence_registry(self):
        '''Calls Velociraptor to check the User Profile Registry for signs of Persistence.'''
        query = """
        SELECT *
        FROM Artifact.Windows.Persistence.PowershellRegistry()
        """
        filename = 'powershell_persistence_results'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)


    def powershell_module(self):
        '''Calls Velociraptor for event log 4103 to extract Module Events.'''
        query = """
        SELECT * 
        FROM Artifact.Windows.Eventlogs.PowershellModule()
        """
        filename = 'powershell_module_results'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)
