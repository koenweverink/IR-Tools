import json, os, datetime

from pathlib import Path

from Script_event_logs import ParseEventLogs
from Script_filesystem import ParseFilesystem
from Script_registry_files import ParseRegistry
from Script_MFT import ParseMFT
from velociraptor.main import Velociraptor


class maliciousWMI:
    ''' This script is used to collect all eventlogs that can indicate the malicious use of WMI (Destination).'''
    def __init__(self, path):
        ''':param path: str'''
        super().__init__()

        # Place all the paths here
        self.SYSTEM_evtx = r'C:\Windows\System32\winevt\Logs\System.evtx'
        self.SYSTEM_reg = r'C:\Users\koenw\Desktop\School\Afstuderen\IR-Tools\Registries\SYSTEM'
        self.Prefetch = 'C:\Windows\Prefetch'
        # self.Amcache = r'C:\Windows\appcompat\Programs\Amcache.hve'

        # Path and results folder
        self.path = path
        self.folder = 'wmi_results'
        
        # Malware to look for
        self.malware = ''
        self.overig = True

        # Initialize scripts Eline
        self.p = ParseEventLogs(self.path, self.folder)
        self.f = ParseFilesystem(self.path, self.folder, self.malware, self.overig)
        self.r = ParseRegistry(self.path, self.folder, self.malware, self.overig)
        self.m = ParseMFT(self.path, self.folder, self.malware, self.overig)
        self.v = Velociraptor()

        self.today = str(datetime.date.today())
        paths = os.path.join(self.path, self.folder)
        Path(paths).mkdir(parents=True, exist_ok=True)

    def security(self):
        """
        UNDER DEVELOPMENT.
        Looks in Security.evtx for:
        - 4624 Logon type 3, followed by 4672 logon with admin rights,
        - 4688 Process was created.
        """
        pass

    
    def wmi_activity(self):
        """
        UNDER DEVELOPMENT.
        Looking in Microsoft-Windows-WMI-Activity%4Operational.evtx for:
        - 5857: wmiprvse.exe execution time,
        - 5860, 5861: Registration of temporary (5860) and permanent (5861) event consumers. This is often used for persistency!
        """
        pass


    def wmi_system(self):
        """
        In SYSTEM registry: \CurrentControlSet\Control\SessionManager\AppCompatCache, look for: 
        - scrcons.exe, 
        - mofcomp.exe, 
        - wmiprvse.exe, 
        - malware.exe.
        """
        self.r.AppCompatCache(self.SYSTEM_reg)

    
    def wmi_amcache(self):
        """
        In Amcache.hve look for:
        - scrcons.exe, 
        - mofcomp.exe, 
        - wmiprvse.exe, 
        - malware.exe.
        """
        self.r.Amcache(self.Amcache)


    def wmi_prefetch(self):
        """
        In C:\Windows\Prefetch look for:
        - scrcons.exe, 
        - mofcomp.exe, 
        - wmiprvse.exe, 
        - malware.exe.
        """
        self.f.prefetch(self.Prefetch)


    def wmi_filesystem(self):
        ''' In the File System look for File creation: “malware.exe” and “malware.mof”.'''
        self.m.parse_mft()


    def wmi_persistence(self):
        '''Calling Velociraptor to check for WMI Persistence.'''
        query = """
        SELECT *
        From Artifact.Windows.Persistence.PermanentWMIEvents()
        """
        filename = 'wmi_persistence'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)

    
    def wmi_amcache_velo(self):
        """Using Velociraptor to get Amcache. Look for:
        - scrcons.exe, 
        - mofcomp.exe, 
        - wmiprvse.exe, 
        - malware.exe.
        """
        query = """
        SELECT *
        FROM Artifact.Windows.System.Amcache()
        WHERE name = 'wmiprvse.exe'
        OR name = 'mofcomp.exe'
        OR name = 'scrcons.exe'
        """
        filename = 'amcache'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)
