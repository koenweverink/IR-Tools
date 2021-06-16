import os.path, time
import datetime
import logging
from pathlib import Path

class ParseFilesystem:
    '''
    This script parses and analyses the Filesystem.
    Here are the variables that need to be defined by the user.
    - AutomaticDestination t/m User_Profile: Path to location to look. 
    - map: The folder where the txt- and log-files end up. 
    - path: The path to the map. 

    Filters can be used for a number of components, so that a more targeted search can be performed.
    The filters available are malware, other malware, created date and modified date.
    When the filter is True, the filter is used.
    If False is entered, the filter is not used and all data is simply retrieved.

    - malware_...: Indicates whether or not to search for the entered malware.
    - other_...: Indicates whether or not to search for commonly used malware.
    - created_date_...: Indicates whether or not to search within the entered date range of the created date.
    - mod_datum_...: Indicates whether or not to search within the entered date range of the modified date.
    - m_...: The malware to search for when malware_... is True.
    - d1_...: The start date of the date range within which to search.
    - d2_...: The end date of the date range within which the search is performed.
    '''

    def __init__(self, path, folder, malware, overig):
        '''
        All the used variables.
        :param path: str
        :param folder: str
        :param malware: str
        :param overig: bool
        '''
        super().__init__()

        self.AutomaticDestination = ''
        self.AutoRecover = ''
        Repository = ''
        Tasks = ''
        Tasks_Migrated = ''
        System32_Tasks = ''
        User_Profile = ''
        map = folder
        path = path

        if malware == '':
            self.malware_prefetch = False
        else:
            self.malware_prefetch = True
        self.overig_prefetch = overig
        self.created_datum_prefetch = False
        self.mod_datum_prefetch = False
        self.m_prefetch = malware
        self.d1_prefetch = ''
        self.d2_pretecht = ''

        self.malware_tasks = False
        created_datum_tasks = False
        mod_datum_tasks = False
        m_tasks = ''
        d1_tasks = ''
        d2_tasks = ''

        self.malware_system32_tasks = False
        created_datum_system32_tasks = False
        mod_datum_system32_tasks = False
        m_system32_tasks = ''
        d1_system32_tasks = ''
        d2_system32_tasks = ''

        self.malware_tasks_migrated = False
        created_datum_tasks_migrated = False
        mod_datum_tasks_migrated = False
        m_tasks_migrated = ''
        d1_tasks_migrated = ''
        d2_tasks_migrated = ''

        self.malware_repository = False
        m_Repository = ''

        self.malware_AutoRecover = False
        m_AutoRecover = ''


        today = str(datetime.date.today())
        paths = os.path.join(path, map)

        Path(paths).mkdir(parents=True, exist_ok=True)

        filename_txt = str(path + map + '//filesystem' + today + '.txt')
        filename_log = str(path + map + '//filesystem' + today + '.log')

        logging.basicConfig(format='[%(asctime)s] - %(message)s',
                                level=logging.DEBUG,
                                datefmt='%Y/%m/%d %I:%M:%S',
                                filename= filename_log,
                                filemode='w'
                                )

        logging.info("Map {} is created.".format(map))
        self.f = open(filename_txt, 'w')
        logging.info("Script registry files has started.")

        self.malware = [
            'rdpclip.exe',
            'tstheme.exe',
            'psexecsvc.exe',
            'WMIPRVSE.EXE',
            'mofcomp.exe',
            'wsmprovhost.exe',
            'ssh.exe',
            'scp.exe',
            'sftp.exe',
        ]


    def header(self, msg):
        '''
        Creates a header for the log file.
        :param msg: str
        '''
        self.f.write('-' * 80 + '\n')
        self.f.write(msg + '\n')
        self.f.write('-' * 80 + '\n')
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


    def last_modified(self, path):
        '''
        Get last modified date.
        :param path: str
        '''
        return str(datetime.datetime.strptime(time.ctime(os.path.getmtime(path)), "%a %b %d %H:%M:%S %Y"))


    def created(self, path):
        '''
        Get creation date.
        :param path: str
        '''
        return str(datetime.datetime.strptime(time.ctime(os.path.getctime(path)), "%a %b %d %H:%M:%S %Y"))


    def split(self):
        '''
        Splits lines in lijst.txt.
        '''
        filetxt = open("lijst.txt", "r")
        list_of_lists = []
        for line in filetxt:
            stripped_line = line.strip()
            line_list = stripped_line.split()
            list_of_lists.append(line_list)
        return list_of_lists


    def prefetch(self, Prefetch):
        '''
        Parsing and analysing Prefetch.
        :param Prefetch: path to Prefetch
        :type Prefetch: str
        '''
        # self.header('Prefetch')
        for dirpath, dirname, files in os.walk(Prefetch):
            for file in files:
                path = str(dirpath + '//' + file)
                output = str('Map: {} - File: {} - Last modified date: {} - Date created: {}'.format(dirpath, file, self.last_modified(path), self.created(path)))

                # Filter: malware
                if self.malware_prefetch and not self.created_datum_prefetch and not self.mod_datum_prefetch and not self.overig_prefetch:
                    if self.m_prefetch.lower() == file.lower():
                        self.f.write(output + '\n')

                # Filter: overige malware
                if not self.malware_prefetch and not self.created_datum_prefetch and not self.mod_datum_prefetch and self.overig_prefetch:
                    for mal in self.malware:
                        if mal.lower() in file.lower():
                            self.f.write(output + '\n')

                # Filter: created date
                if not self.malware_prefetch and self.created_datum_prefetch and not self.mod_datum_prefetch and not self.overig_prefetch:
                    filter_datum(self.d1_prefetch, self.d2_pretecht, last_modified(path), output)

                # Filter: last modified date
                if not self.malware_prefetch and not self.created_datum_prefetch and self.mod_datum_prefetch and not self.overig_prefetch:
                    filter_datum(self.d1_prefetch, self.d2_pretecht, created(path), output)

                # Filter: malware + created
                if self.malware_prefetch and self.created_datum_prefetch and not self.mod_datum_prefetch and not self.overig_prefetch:
                    if self.m_prefetch.lower() == file.lower():
                        filter_datum(self.d1_prefetch, self.d2_pretecht, last_modified(path), output)

                # Filter: malware + last modified date
                if self.malware_prefetch and not self.created_datum_prefetch and self.mod_datum_prefetch and not self.overig_prefetch:
                    if self.m_prefetch.lower() == file.lower():
                        filter_datum(self.d1_prefetch, self.d2_pretecht, created(path), output)

                # Filter: malware + overige malware
                if self.malware_prefetch and not self.created_datum_prefetch and not self.mod_datum_prefetch and self.overig_prefetch:
                    for mal in self.malware:
                        if mal.lower() == file.lower():
                            self.f.write(output + '\n')

                    if self.m_prefetch.lower() == file.lower():
                        self.f.write(output + '\n')

                # Filter: geen
                if not self.malware_prefetch and not self.created_datum_prefetch and not self.mod_datum_prefetch and not self.overig_prefetch:
                    self.f.write(output + '\n')
            
        self.f.close()     

if __name__ == "__main__":
    p = ParseFilesystem(r'C:\Users\koenw\Desktop\School\Afstuderen\Results\\', 'wmi_results', '', False)
    print(help(p))