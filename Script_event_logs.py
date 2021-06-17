import os
import xml_functies
import csv_functies
import datetime
import logging

from pathlib import Path

class ParseEventLogs:
    '''
    This script parses and analyses event logs.
    Below are the variables that need to be defined by the user.
    - Aapplication t/m WimPowerShell: path to the event logs.
    - map: de map where the xml-, csv- and log-files end up in. 
    - path: the path to the map. 
    '''
    def __init__(self, path, folder):
        '''
        All the used variables.
        :param path: string
        :param folder: string
        '''
        super().__init__()

        self.Application = 'C:\Windows\System32\winevt\Logs\Application.evtx'
        # self.WinPowerShell_O = ''
        self.RDS_LocalSession = ''
        self.RDS_RdpCoreTS = ''
        self.TaskScheduler = ''
        self.TS_LocalSessionMgr = ''
        self.TS_RemoteConnectionMgr = ''
        self.TS_RemoteSessionMgr = ''
        self.WinRM = ''
        self.WMI = 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx'
        self.Security = 'C:\Windows\System32\winevt\Logs\Security.evtx'
        # self.System = 'C:\Windows\System32\winevt\Logs\System.evtx'
        self.WinPowerShell = 'C:\Windows\System32\winevt\Logs\Windows Powershell.evtx'
        self.map = folder
        self.path = path

        self.today = str(datetime.date.today())
        self.paths = os.path.join(self.path, self.map)
        
        Path(self.paths).mkdir(parents=True, exist_ok=True)
        # os.mkdir(self.paths)

        self.event_log = str(self.path + self.map + '//event' + self.today + '.log')

        logging.basicConfig(format='[%(asctime)s] - %(message)s',
                            level=logging.DEBUG,
                            datefmt='%Y/%m/%d %I:%M:%S',
                            filename= self.event_log,
                            filemode='w'
                            )

        logging.info("self.map {} is created.".format(self.map))

    # System (7040)
    def system_7040(self, System):
        '''
        Look for event ID 7040 in System.evtx.
        :param System: path to System.evtx
        :type System: str
        '''
        result = xml_functies.xml_7040(System, self.path, self.map, self.today)
        for file in os.listdir(self.paths):
            if file == 'xml_7040_' + self.today + '.xml':
                output_xml = 'File xml.7040_' + self.today + '.xml is toegevoegd aan de map: ' + self.map
                csv_functies.csv_7040(self.path, self.map, self.today)
                for file2 in os.listdir(self.paths):
                    if file2 == 'csv_7040_' + self.today + '.csv':
                        output_csv = 'File csv.7040_' + self.today + '.csv is toegevoegd aan de map: ' + self.map
        return result, output_xml, output_xml

    # System (7045)
    def system_7045(self, System):
        '''
        Look for event ID 7045 in System.evtx.
        :param System: path to System.evtx
        :type System: str
        '''
        result = xml_functies.xml_7045(System, self.path, self.map, self.today)
        for file in os.listdir(self.paths):
            if file == 'xml_7045_' + self.today + '.xml':
                output_xml = 'File xml.7045_' + self.today + '.xml is toegevoegd aan de map: ' + self.map 
                csv_functies.csv_7045(self.path, self.map, self.today)
                for file2 in os.listdir(self.paths):
                    if file2 == 'csv_7045_' + self.today + '.csv':
                        output_csv = 'File csv.7045_' + self.today + '.csv is toegevoegd aan de map: ' + self.map
        return result, output_xml, output_csv


    # Windows-PowerShell (53504)
    def windows_powershell_53504(self, WinPowerShell_O):
        '''
        Look for event ID 53504 in Microsoft-Windows-PowerShell%4Operational.evtx.
        :param WinPowerShell_O: path to Microsoft-Windows-PowerShell%4Operational.evtx
        :type WinPowerShell_O: str
        '''
        result = xml_functies.xml_53504(WinPowerShell_O, self.path, self.map, self.today)
        for file in os.listdir(self.paths):
            if file == 'xml_53504_' + self.today + '.xml':
                output_xml = 'File xml.53504_' + self.today + '.xml is toegevoegd aan de map: ' + self.map
                csv_functies.csv_53504(self.path, self.map, self.today)
                for file2 in os.listdir(self.paths):
                    if file2 == 'csv_53504_' + self.today + '.csv':
                        output_csv = 'File csv.53504_' + self.today + '.csv is toegevoegd aan de map: ' + self.map
        return result, output_xml, output_csv


    def windows_powershell_4104(self, WinPowerShell_O):
        """
        Look for event ID 4104 in Microsoft-Windows-PowerShell%4Operational.evtx.
        :param WinPowerShell_O: path to Microsoft-Windows-PowerShell%4Operational.evtx
        :type WinPowerShell_O: str
        """
        # output of csv needs some change
        result = xml_functies.xml_4104(WinPowerShell_O, self.path, self.map, self.today)
        for file in os.listdir(self.paths):
            if file == 'xml_4104_' + self.today + '.xml':
                output_xml = 'File xml.4104_' + self.today + '.xml is toegevoegd aan de map: ' + self.map
                csv_functies.csv_4104(self.path, self.map, self.today)
                for file2 in os.listdir(self.paths):
                    if file2 == 'csv_4104_' + self.today + '.csv':
                        output_csv = 'File csv.4104_' + self.today + '.csv is toegevoegd aan de map: ' + self.map
        return result, output_xml, output_csv
