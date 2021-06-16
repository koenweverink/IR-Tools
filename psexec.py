import os, datetime

from pathlib import Path

from Script_event_logs import ParseEventLogs
from Script_filesystem import ParseFilesystem
from Script_registry_files import ParseRegistry
from velociraptor.main import Velociraptor

class maliciousPsExec:
    '''This script is used to collect all eventlogs that can indicate the malicious use of PsExec (Destination).'''
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
        self.folder = 'psexec_results'
        
        # Malware to look for
        self.malware = 'psexecsvc.exe'
        self.overig = False

        # Initialize scripts Eline
        self.p = ParseEventLogs(self.path, self.folder)
        self.f = ParseFilesystem(self.path, self.folder, self.malware, self.overig)
        self.r = ParseRegistry(self.path, self.folder, self.malware, self.overig)
        self.v = Velociraptor()

        self.today = str(datetime.date.today())
        paths = os.path.join(self.path, self.folder)
        Path(paths).mkdir(parents=True, exist_ok=True)

    def system_7045(self):
        '''Finds event log 7045 (service install) in system.evtx, and outputs it to the selected folder.'''
        result, output_xml, output_csv = self.p.system_7045(self.SYSTEM_evtx)
        return result, output_xml, output_csv


    def prefetch_psexec(self):        
        '''Looking in C:\Windows\Prefetch for psexecsvc.exe-<HASH>.pf, and outputs it to the selected folder.'''
        self.f.prefetch(self.Prefetch)


    def Amcache_psexec(self):
        '''Looking in C:\Windows\AppCompat\Programs\Amcache.hve for psexecsvc.exe, and outputs it to the selected folder.'''
        self.r.Amcache(self.Amcache)


    def system_psexesvc(self):
        """In the SYSTEM Registry look for \CurrentControlSet\Services\PSEXESVC
         (might be renamed, try to correlate with SOURCE machine for right name).
         In \CurrentControlSet\Control\Session Manager\AppCompatCache look for PsExecSvc (ShimCache), and outputs it to the selected folder."""
        self.r.PSEXECSVC(self.SYSTEM_reg)
        self.r.AppCompatCache(self.SYSTEM_reg)

    
    def security(self):
        """
        UNDER DEVELOPMENT.
        In Security.evtx look for:
        4624 Logon Type 3 (and 2): Source IP and user,
        4672 Logon Username,
        5140 Share access, ADMIN$ used by PsExec,
        4688 A process has been created (if enabled); 4689 Process exited."""
        pass


    def service_creation_7045(self):
        '''Look for COMPSEC in event log 7045 using Velociraptor, and outputs it to the selected folder.'''
        query = """
        SELECT * 
        FROM Artifact.Windows.Eventlogs.ServiceCreationCompsec()
        """
        filename = 'psexec_servicecreation_results'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)    


    def psexec_amcache(self):
        '''Get AmCache.hve using Velociraptor where the name is psexecsvc.exe, and outputs it to the selected folder.'''
        query = """
        SELECT * 
        FROM Artifact.Windows.System.Amcache()
        WHERE name = 'psexecsvc.exe'
        """
        filename = 'amcache'
        destination = str(self.path + self.folder + '//{}' + self.today + '.json').format(filename)
        self.v.query(query, destination)
