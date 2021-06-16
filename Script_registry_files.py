from regipy.registry import RegistryHive, convert_wintime
import datetime
import logging
import os
from pathlib import Path


class ParseRegistry:
    """
    This script parses and analyses the registry.
    Here are the variables that must be filled in by the user.
    - SYSTEM to NTUSER: Path to the event log in which to search.
    - map: The map where the txt and log file end up when the code is run.
    - path: The path where the map should go.

    Filters can be used for a number of components, so that a more targeted search can be made.
    The filters available are malware, other malware, name, SID and date.
    When the filter is True, the filter is used.
    If False is entered, the filter is not used and all data is simply retrieved.

    - malware_...: Indicates whether or not to search for the entered malware.
    - other_...: Indicates whether or not to search for commonly used malware.
    - name_...: Indicates whether or not to search for the entered subself.keyname.
    - SID_...: Indicates whether or not to search for the entered SID.
    - date_...: Indicates whether or not to search within the entered date range.
    - m_...: The malware being searched for.
    - n_...: The subkeyname to search for.
    - SID_d /SID_b: The SID to search for.
    - d1_...: The start date of the date range within which to search.
    - d2_...: The end date of the date range within which to search.
    """
    def __init__(self, path, folder, malware, overig):
        '''
        All the used variables.
        :param path: str
        :param folder: str
        :param malware: str
        :param overig: bool
        '''
        super().__init__()

        self.map = folder
        self.path = path

        self.malware_AppCompatCache = True
        self.overig_AppCompatCache = overig
        self.m_AppCompatCache = malware

        datum_service = False
        name_service = False
        n_service = ''
        d1_service = ''
        d2_service = ''

        name_tasks = False
        datum_tasks = False
        n_tasks = ''
        d1_tasks = ''
        d2_tasks = ''

        name_tree = False
        datum_tree = False
        n_tree = ''
        d1_tree = ''
        d2_tree = ''

        SID_bam = False
        SID_b = ''

        SID_dam = False
        SID_d = ''

        self.malware_amcache = True
        self.m_amchache = malware

        today = str(datetime.date.today())
        paths = os.path.join(self.path, self.map)

        Path(paths).mkdir(parents=True, exist_ok=True)

        registry_txt = str(self.path + self.map + '//registry' + today + '.txt')
        registry_log = str(self.path + self.map + '//registry' + today + '.log')

        logging.basicConfig(format='[%(asctime)s] - %(message)s',
                                level=logging.DEBUG,
                                datefmt='%Y/%m/%d %I:%M:%S',
                                filename= registry_log,
                                filemode='w'
                                )

        logging.info("Map {} is created.".format(self.map))
        self.f = open(registry_txt, 'w')
        logging.info("Script registry files has started.")

        self.key = [
            '\\ControlSet001\\Control\\SessionManager\\AppCompatCache\\AppCompatCache',
            '\\ControlSet001\\Services',
            '\\ControlSet001\\Services\\PSEXECSVC',
            '\\ControlSet001\\Services\\bam\\UserSettings',
            '\\ControlSet001\\Services\\dam\\UserSettings',
            '\\Root\\InventoryApplicationFile',
            '\\Root\\File',
            '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist',
            '\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps',
            '\\Microsoft\\WBEM\\CIMOM\\AutoRecoverMOF',
            '\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell',
            '\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks',
            '\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree',
        ]

        self.malware = [
            'rdpclip.exe',
            'tstheme.exe',
            'psexecsvc',
            'wmiprvse.exe',
            'mofcomp.exe',
            'wsmprovhost.exe',
        ]


    def header(self, msg):
        '''
        Creates a header for the log file.
        :param msg: str
        '''
        self.f.write('*' * 80 + '\n')
        self.f.write(msg + '\n')
        self.f.write('*' * 80 + '\n')
        logging.info("Searching in {}".format(msg))


    def filter_datum(self, datum1, datum2, searchdate, output):
        '''
        Creates the time filters if necessary.
        :param datum1: str
        :param datum2: str
        :param searchdate: datetime
        :param output:str
        '''
        start = datetime.datetime.strptime(datum1, "%Y-%m-%d")
        end = datetime.datetime.strptime(datum2, "%Y-%m-%d")
        date_generated = [start + datetime.timedelta(days=x) for x in range(0, (end - start).days)]
        for date in date_generated:
            if date.strftime("%Y-%m-%d") == searchdate[:10]:
                self.f.write(output + '\n')
        if datum2[:10] == searchdate[:10]:
            self.f.write(output + '\n')


    def end(self, name):
        '''
        Decides how the loggig ends.
        :param name: str
        '''
        if 'fil' in globals():
            logging.info('Results for {}'.format(name))
        elif 'fil' not in globals():
            logging.info('No results for {}'.format(name))


    def date(self, sk):
        '''
        Converts last modified time.
        :param sk: str
        '''
        return str(convert_wintime(sk.header.last_modified))


    def AppCompatCache(self, SYSTEM):
        '''
        All executables and the path of executables that are in 'AppCompatCache' are retrieved and analysed.
        In addition, the Last modified date of the executables is also retrieved.

        :param SYSTEM: Path to SYSTEM registry
        :type SYSTEM: str
        '''
        # self.header('AppCompatCache')
        from regipy.plugins.system.shimcache import ShimCachePlugin
        reg = RegistryHive(SYSTEM)
        ShimCachePlugin(reg, as_json=True).run()
        plugin = ShimCachePlugin(reg, as_json=True)
        plugin.run()
        for x in range(len(plugin.entries)):
            self.path = plugin.entries[x]['path']
            time = plugin.entries[x]['last_mod_date']
            output = str('Key: {} - Path: {} - Last modified date: {}'.format(self.key[0], self.path, time))

            if self.malware_AppCompatCache and not self.overig_AppCompatCache:
                c = len(self.m_AppCompatCache)
                if self.path[-c:].lower() == self.m_AppCompatCache.lower():
                    self.f.write(output + '\n')

            if not self.malware_AppCompatCache and self.overig_AppCompatCache:
                for mal in self.malware:
                    c = len(mal)
                    if self.path[-c:].lower() == mal.lower():
                        self.f.write(output + '\n')

            if self.malware_AppCompatCache and self.overig_AppCompatCache:
                c = len(self.m_AppCompatCache)
                if self.path[-c:].lower() == self.m_AppCompatCache.lower():
                    self.f.write(output + '\n')

                for mal in self.malware:
                    c = len(mal)
                    if self.path[-c:].lower() == mal.lower():
                        self.f.write(output + '\n')

            if not self.malware_AppCompatCache and not self.overig_AppCompatCache:
                self.f.write(output + '\n')
        
        self.f.close()


    def PSEXECSVC(self, SYSTEM):
        '''
        Looking for PSEXECSVC in the SYSTEM Registry and writes the name, value, type and corruption to the specified file.
        :param SYSTEM: path to SYSTEM Registry
        :type SYSTEM: str
        '''
        # self.header('PSEXECSVC')
        reg = RegistryHive(SYSTEM)

        for sk in reg.get_key(self.key[1]).iter_subkeys():
            if sk.name == 'PSEXECSVC':
                self.f.write('Key: {} - Last modified date: {}\n'.format(self.key[2], date(sk)))
                for val in sk.get_values():
                    name = val.name
                    value = val.value
                    type = val.value_type
                    cor = val.is_corrupted
                    f.write('Value name: {} - Value: {} - Value type: {} - Is corrupted: {}\n'.format(name, value, type, cor))

        self.f.close()


    def Amcache(self, Amcache):
        '''
        Amcache (InventoryApplicationFile):
        The date is the last modified date of the subkeys in the subkey 'InventoryApplicationFile'.
        The subkeys all contain different values, one of which is the value 'LowerCaseLongPath'.
        This contains the path and the executable.
        '''
        self.header('Amcache')
        reg = RegistryHive(Amcache)
        try:
            for sk in reg.get_self.key(self.key[5]).iter_subself.keys():
                for val in sk.get_values():
                    if val.name == 'LowerCaseLongPath':
                        output = str('Key: {} - Path: {} - Disk volume: {} - Last modified date: {}\n'.format(self.key[5], val.value, val.value[:1], date(sk)))

                        if not self.malware_amcache:
                            f.write(output + '\n')

                        if self.malware_amcache:
                            c = len(self.m_amchache)
                            if val.value[-c:].lower() == self.m_amchache.lower():
                                f.write(output + '\n')

        except:
            logging.info("'Root' doesn't contain the subself.key 'InventoryApplicationFile'.")

        '''
        Amcache (File):
        ....
        '''
        try:
            for sk in reg.get_self.key(self.key[6]).iter_subself.keys():
                for val in sk.get_values():
                    if val.name == 'LowerCaseLongPath':
                        output = str('Key: {} - Path: {} - Disk volume: {} - Last modified date: {}\n'.format(self.key[6], val.value, val.value[:1], date(sk)))

                        if not self.malware_amcache:
                            f.write(output + '\n')

                        if self.malware_amcache:
                            c = len(self.m_amchache)
                            if val.value[-c:].lower() == self.m_amchache.lower():
                                f.write(output + '\n')

        except:
            logging.info("'Root' doesn't contain the subkey 'File'.")

        self.f.close()
