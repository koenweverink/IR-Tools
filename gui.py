from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkcalendar import DateEntry

import os, datetime, shutil

from Script_event_logs import ParseEventLogs
from powershell import maliciousPowershell
from psexec import maliciousPsExec
from wmi import maliciousWMI
from DeepBlueCLI import DeepBlueCLI
from cred_dump import CredentialDump

class CollectAndAnalyse:
    '''
    This is the main script for the tool. It starts the GUI and calls all the other scripts to action. 
    '''
    def __init__(self, root):
        '''
        Here is all the content of the GUI placed.
        :param root: Initialize a blank window to work with.
        :type root: tK() function.
        '''
        super().__init__()

        root.title("Collect and Analyse")

        self.mainframe = ttk.Frame(root, padding="3 3 12 12")
        self.mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        ttk.Label(self.mainframe, text="Select Action:").grid(column=1, row=1, sticky=(N, W))

        self.option_velociraptor = BooleanVar()
        self.option_velociraptor.set(False)
        ttk.Checkbutton(self.mainframe, text="Velociraptor Analysis", variable=self.option_velociraptor).grid(column=1, row=2, sticky=W)

        self.option_DI = BooleanVar()
        self.option_DI.set(True)
        ttk.Checkbutton(self.mainframe, text="Digital Investigation Analysis", variable=self.option_DI).grid(column=1, row=3, sticky=W)

        ttk.Label(self.mainframe, text="Select Host:").grid(column=1, row=4, sticky=(N, W), pady=(10, 0))
        
        choices = ['host1', 'host2', 'host3', 'host4', 'etc.']
        choicesvar = StringVar(value=choices)
        listBox = Listbox(self.mainframe, height=5, listvariable=choicesvar)
        listBox.grid(column=1, row=5, sticky=(W))

        ttk.Label(self.mainframe, text="Triaging:").grid(column=1, row=6, sticky=(N, W), pady=(10,0))
        
        self.option_DBCLI = BooleanVar()
        chk_dbcli = ttk.Checkbutton(self.mainframe, text="DeepBlueCLI", variable=self.option_DBCLI).grid(column=1, row=7, sticky=(N, W))

        ttk.Label(self.mainframe, text="Select TTP:").grid(column=1, row=8, sticky=(N, W), pady=(10, 0))

        self.option_Top5 = BooleanVar()
        chk_t5 = ttk.Checkbutton(self.mainframe, text="Top 5", variable=self.option_Top5, 
            command=self.change_state).grid(column=1, row=9, sticky=W)

        self.option_PS = BooleanVar()
        self.chk_ps = ttk.Checkbutton(self.mainframe, text="Powershell", variable=self.option_PS)
        self.chk_ps.grid(column=1, row=10, sticky=W)

        self.option_WMI = BooleanVar()
        self.chk_wmi = ttk.Checkbutton(self.mainframe, text="WMI", variable=self.option_WMI)
        self.chk_wmi.grid(column=1, row=11, sticky=W)

        self.option_PsExec = BooleanVar()
        self.chk_psexec = ttk.Checkbutton(self.mainframe, text="PsExec", variable=self.option_PsExec)
        self.chk_psexec.grid(column=2, row=9, sticky=W)

        self.option_Masq = BooleanVar()
        self.chk_masq = ttk.Checkbutton(self.mainframe, text="Masquerading", variable=self.option_Masq)
        self.chk_masq.grid(column=2, row=10, sticky=W)

        self.option_Cred = BooleanVar()
        self.chk_cred = ttk.Checkbutton(self.mainframe, text="Credential Dumping", variable=self.option_Cred, command=self.show_fldr_cred)
        self.chk_cred.grid(column=2, row=11, sticky=W)
        self.cred_button = ttk.Button(self.mainframe, text="Browse", command=self.browse_cred_folder)


        ttk.Label(self.mainframe, text='Destination folder:').grid(column=1, row=17, sticky=(N, W), pady=(10, 0))
        ttk.Button(self.mainframe, text='Browse', command=self.destination_folder).grid(column=1, row=18, sticky=(W))

        ttk.Button(self.mainframe, text="Analyse", command=self.retrieve_data).grid(column=1, row=19, sticky=(S), pady=(10, 0))

        self.output = Text(self.mainframe, width=40, height=10, wrap=None)
        ys = ttk.Scrollbar(self.mainframe, orient='vertical', command=self.output.yview)
        self.output['yscrollcommand'] = ys.set
        self.output.grid(column=1, row=20, sticky=(N, W, E, S), pady=(10, 0), columnspan=2)
        self.output['state'] = 'disabled'
        self.output.see('end')
        ys.grid(column=3, row=20, sticky='nsw', pady=(10, 0))


    def destination_folder(self):
        '''
        A separate function to define the folder into which the results are placed.
        '''
        folder = filedialog.askdirectory()
        self.dfolderpath = StringVar()
        self.dfolderpath.set(folder)
        self.dfolder_lbl = Label(self.mainframe, textvariable=self.dfolderpath)
        self.dfolder_lbl.grid_forget()
        self.dfolder_lbl.grid(column=2, row=18, sticky=(W))


    def show_fldr_cred(self):
        '''
        A function to decide whether or not a button is show underneath the Credential Dumping option. 
        '''
        if self.option_Cred.get() == True:
            self.cred_button.grid(column=2, row=12, sticky=(W))
        else:
            self.cred_button.grid_forget()
            self.folder_lbl.grid_forget( )


    def browse_cred_folder(self):
        '''
        A separate function to define the folder into which the tool will look for traces of Credential Dumping.
        '''
        foldername = filedialog.askdirectory()
        self.folder_path_cred = StringVar()
        self.folder_path_cred.set(foldername)
        self.folder_lbl_cred = Label(self.mainframe, textvariable=self.folder_path_cred)
        self.folder_lbl_cred.grid_forget()
        self.folder_lbl_cred.grid(column=2, row=13, sticky=(W))


    def change_state(self):
        '''
        Changes the state of the rest of the options to 'Normal' or 'Disabled' whenever the option for the top five is selected or deselected.
        '''
        if self.option_Top5.get() == True:
            self.option_PS.set(True)
            self.chk_ps.config(state=DISABLED)
            self.option_WMI.set(True)
            self.chk_wmi.config(state=DISABLED)
            self.option_PsExec.set(True)
            self.chk_psexec.config(state=DISABLED)
            self.option_Masq.set(True)
            self.chk_masq.config(state=DISABLED)
            self.option_Cred.set(True)
            self.chk_cred.config(state=DISABLED)
        else:
            self.option_Top5.set(False)
            self.option_PS.set(False)
            self.chk_ps.configure(state='normal')
            self.option_WMI.set(False)
            self.chk_wmi.configure(state='normal')
            self.option_PsExec.set(False)
            self.chk_psexec.configure(state='normal')
            self.option_Masq.set(False)
            self.chk_masq.configure(state='normal')
            self.option_Cred.set(False)
            self.chk_cred.configure(state='normal')

    def retrieve_data(self):
        """
        The main function of the tool. Here, is where all the scripts are called from.
        Firstly, it gets all the necessary variables, like the current time, destination folder path and credential dump path.
        Secondly, all the necessary classes are initialized.
        Then, the state of the output box is changed to 'normal' so that output can be generated.
        Next, it will check if the user wants the DeepBlueCLI triage performed, and if so, it will perform it.
        Then, it will check if any of the main actions are selected, if not, it will give an error message.
        Next, it will check if the user has selected the Velociraptor option, and if so, it will check which of the top 5 the user wants analyzed and then perform that analysis.
        Then, it will check if the user has selected the DI option, and if so, it will check which of the top 5 the user wants analyzed and then perform that analysis.
        Finally, the function will end by outputting 'done' and setting the state of the output box back to 'disabled' so that it can't be altered. 
        """
        path = str(self.dfolderpath.get() + '/')
        today = str(datetime.date.today())
        try:
            folder = str(self.folder_path_cred.get())
        except:
            folder = ''
        
        # p = ParseEventLogs(path)
        m = maliciousPowershell(path)
        e = maliciousPsExec(path)
        w = maliciousWMI(path)
        c = CredentialDump(path, folder)


        self.output['state'] = 'normal'
        self.output.insert('end', "Retrieving Data... \n\n")
        self.mainframe.update_idletasks()

        if self.option_DBCLI.get() == True:
            try:
                d = DeepBlueCLI()
                self.output.insert('end', "Starting DeepBlueCLI general triage. This can take a few minutes. Please Wait.\n\n")
                self.mainframe.update_idletasks()
                output = d.deepBlue()
                self.output.insert('end', output)
                self.mainframe.update_idletasks()
            except:
                self.output.insert('end', "Something went wrong.\n\n")

    
        if self.option_velociraptor.get() == False and self.option_DI.get() == False:
            self.output.insert('end', "Please select an Action \n\n")
            self.mainframe.update_idletasks()
            return


        if self.option_velociraptor.get() == True:
            # Powershell
            if self.option_PS.get() == True:
                self.output.insert('end', "SCANNING FOR POTENTIALLY MALICIOUS USE OF POWERSHELL USING VELOCIRAPTOR\n\n")
                
                # Velociraptor Scriptblocking 
                self.output.insert('end', "Looking for traces of Scriptblocking \n")
                self.mainframe.update_idletasks()
                m.powershell_scriptblock()
                try:
                    if os.stat(path + '\\powershell_results\\scriptblock_results' + today + '.json').st_size == 0:
                        self.output.insert('end', "No indication of Script Blocking found\n\n")
                    else:
                        self.output.insert('end', "Results can be found in 'powershell_results/scriptblock_results.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "No indication of Script Blocking found\n\n")
                self.mainframe.update_idletasks()

                # Powershell Registry Persistence 
                self.output.insert('end', "Looking for Powershell Persistence in the User Profile Registry\n")
                self.mainframe.update_idletasks()
                m.powershell_persistence_registry()
                try:
                    if os.stat(path + '\\powershell_results\\powershell_persistence_results' + today + '.json').st_size == 0:
                        self.output.insert('end', "No indication of Persistence using Powershell found\n\n")
                        os.remove(path + '\\powershell_results\\powershell_persistence_results' + today + '.json')
                    else:
                        self.output.insert('end', "Results can be found in 'powershell_results/powershell_persistence_results.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "No indication of Persistence using Powershell found\n\n")
                self.mainframe.update_idletasks()
        
                # Powershell Module evtx 4103 
                self.output.insert('end', "Extracting Powershell Eventlog 4103\n")
                self.mainframe.update_idletasks()
                m.powershell_module()
                try:
                    if os.stat(path + '\\powershell_results\\powershell_module_results' + today + '.json').st_size == 0:
                        self.output.insert('end', "Nothing found in EVTX 4103\n\n")
                    else:
                        self.output.insert('end', "Results can be found in 'powershell_results/powershell_module_results.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "Nothing found with EVTX 4103\n\n")
                self.mainframe.update_idletasks()

            # WMI
            if self.option_WMI.get() == True:
                self.output.insert('end', "SCANNING FOR POTENTIALLY MALICIOUS USE OF WMI USING VELOCIRAPTOR\n\n")

                # WMI Persistence
                self.output.insert('end', "Looking for WMI Persistence\n")
                self.mainframe.update_idletasks()
                w.wmi_persistence()
                try:
                    if os.stat(path + '\\wmi_results\\wmi_persistence' + today + '.json').st_size == 0:
                        self.output.insert('end', "Found no indication of WMI Persistence\n\n")
                    else:
                        self.output.insert('end', "Results can be found in 'wmi_results/wmi_persistence.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "Found no indication of WMI Persistence\n\n")
                self.mainframe.update_idletasks()

                # WMI Amcache
                self.output.insert('end', "Getting Amcache...\n")
                self.mainframe.update_idletasks()
                w.wmi_amcache_velo()
                try:
                    if os.stat(path + '\\wmi_results\\amcache' + today + '.json').st_size == 0:
                        self.output.insert('end', "Found no malicious indicators for WMI in Amcache\n\n")
                    else:
                        self.output.insert('end', "Results can be found in 'wmi_results/amcache.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "Found no malicious indicators for WMI in Amcache\n\n")
                self.mainframe.update_idletasks()
                

            # PsExec
            if self.option_PsExec.get() == True:
                self.output.insert('end', "SCANNING FOR POTENTIALLY MALICIOUS USE OF PSEXEC USING VELOCIRAPTOR\n\n")

                # Service Creation COMPSEC
                self.output.insert('end', "Looking for COMPSEC in EVTX 7045\n")
                self.mainframe.update_idletasks()
                e.service_creation_7045()
                try:
                    if os.stat(path + '\\psexec_results\\psexec_servicecreation_results.json' + today + '.txt').st_size == 0:
                        self.output.insert('end', "Found no COMPSEC in EVTX 7045\n\n")
                    else:
                        self.output.insert('end', "Results can be found in 'psexec_results/psexec_servicecreation_results.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "Found no COMPSEC in EXTX 7045\n\n")
                self.mainframe.update_idletasks()

                # PsExec Amcache
                self.output.insert('end', "Extracting Amcache...\n")
                self.mainframe.update_idletasks()
                e.psexec_amcache()
                try:
                    if os.stat(path + '\\psexec_results\\amcache' + today + '.json').st_size == 0:
                        self.output.insert('end', "Found no malicious indicators for PsExec in Amcache\n\n")
                    else:
                        self.output.insert('end', "Results can be found in 'psexec_results/amcache.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "Found no malicious indicators for PsExec in Amcache\n\n")
                self.mainframe.update_idletasks()
                

            # Credential Dumping
            if self.option_Cred.get() == True:
                self.output.insert('end', "SCANNING FOR CREDENTIAL DUMPING USING VELOCIRAPTOR\n\n")

                # Impersonation
                self.output.insert('end', "Looking for signs of Impersonation\n")
                self.mainframe.update_idletasks()
                c.detect_impersonation()
                try:
                    if os.stat(path + '\\credential_dump_results\\creddump_result' + today + '.json').st_size == 0:
                        self.output.insert('end', "Found no indication of Impersonation\n\n")
                    else:
                        self.output.insert('end', "Results can be found in 'credential_dump_results/creddump_result.json'\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "Found no indication of Impersonation\n\n")
                self.mainframe.update_idletasks()

            
        if self.option_DI.get() == True:
            
            # Powershell
            if self.option_PS.get() == True:
                self.output.insert('end', "SCANNING FOR POTENTIALLY MALICIOUS USE OF POWERSHELL USING DI COLLECTION\n\n")
                
                # eventID 53504
                self.output.insert('end', "Looking for Powershell eventlogs with event ID 53504 \n\n")
                self.mainframe.update_idletasks()
                result_powershell_o, output_xml, output_csv = m.powershell_operational_53504()
                if result_powershell_o != None:
                    self.output.insert('end', result_powershell_o + " found\n\n" + output_xml + "\n\n" + output_csv + "\n\n")
                else:
                    self.output.insert('end', "No Powershell eventlogs found with event ID 53504\n\n")
                self.mainframe.update_idletasks()

                # eventID 4104
                self.output.insert('end', "Looking for Powershell eventlogs with event ID 4104 \n")
                self.mainframe.update_idletasks()
                result_powershell_o, output_xml, output_csv = m.powershell_operational_4104()
                if result_powershell_o != None:
                    self.output.insert('end', result_powershell_o + " found\n\n" + output_xml + "\n\n" + output_csv + "\n\n")
                else:
                    self.output.insert('end', "No Powershell eventlogs found with event ID 4104\n\n")
                self.mainframe.update_idletasks()

                # eventID 4624
                self.output.insert('end', "Looking for Powershell eventlogs with event ID 4624 \n")
                self.mainframe.update_idletasks()
                # m.security_logs()

                # Prefetch
                self.output.insert('end', "Looking for wsmprovhost.exe inside Prefetch \n")
                self.mainframe.update_idletasks()
                m.powershell_filesystem()
                if os.stat(path + '\\powershell_results\\filesystem' + today + '.txt').st_size == 0:
                    self.output.insert('end', "Did not find wsmprovhost.exe inside Prefetch \n\n")
                    os.remove(path + '\\powershell_results\\filesystem' + today + '.txt')
                else:
                    self.output.insert('end', "Found wsmprovhost.exe inside Prefetch! Please check the map: powershell_results.\n\n")
                self.mainframe.update_idletasks()

                # AppCompatCache
                self.output.insert('end', "Looking for wsmprovhost.exe inside AppCompatCache \n")
                self.mainframe.update_idletasks()
                m.system_reg()
                if os.stat(path + '\\powershell_results\\registry' + today + '.txt').st_size == 0:
                    self.output.insert('end', "Did not find wsmprovhost.exe inside AppCompatCache \n\n")
                    os.remove(path + '\\powershell_results\\registry' + today + '.txt')
                else:
                    self.output.insert('end', "Found wsmprovhost.exe inside AppCompatCache! Please check the map: powershell_results.\n")
                self.mainframe.update_idletasks()


            if self.option_PsExec.get() == True:
                self.output.insert('end', "SCANNING FOR POTENTIALLY MALICIOUS USE OF PSEXEC USING DI COLLECTION\n\n")
                # EventID 7045
                self.output.insert('end', "Looking inside the System eventlog for eventID 7045 \n")
                self.mainframe.update_idletasks()
                result_ps, output_xml, output_csv = e.system_7045()
                self.output.insert('end', result_ps + " found\n\n" + output_xml + "\n\n" + output_csv + "\n\n")
                self.mainframe.update_idletasks()

                # Prefetch
                self.output.insert('end', "Looking for psexecsvc.exe inside Prefetch \n")
                self.mainframe.update_idletasks()
                e.prefetch_psexec()
                if os.stat(path + '\\psexec_results\\filesystem' + today + '.txt').st_size == 0:
                    self.output.insert('end', "Did not find psexecsvc.exe inside Prefetch \n\n")
                    os.remove(path + '\\psexec_results\\filesystem' + today + '.txt')
                else:
                    self.output.insert('end', "Found psexecsvc.exe inside Prefetch! Please check the map: psexec_results.\n\n")
                    self.mainframe.update_idletasks()

                # Amcache
                self.output.insert('end', "Looking for psexecsvc.exe inside Amcache \n")
                self.mainframe.update_idletasks()
                # e.Amcache_psexec()
                if os.stat(path + '\\psexec_results\\registry' + today + '.txt').st_size == 0:
                    self.output.insert('end', "Did not find psexecsvc.exe inside Amcache \n\n")
                    # os.remove(path + '\\psexec_results\\registry' + today + '.txt')
                else:
                    self.output.insert('end', "Found psexecsvc.exe inside Amcache! Please check the map: psexec_results.\n\n")
                    self.mainframe.update_idletasks()

                # \CurrentControlSet\Services\PSEXESVC
                self.output.insert('end', "Looking for PSEXESVC inside Services and AppCompatCache \n")
                self.mainframe.update_idletasks()
                e.system_psexesvc()
                try:
                    if os.stat(path + '\\psexec_results\\services_registry' + today + '.txt').st_size == 0:
                        self.output.insert('end', "Did not find PSEXESVC inside Services or AppCompatCache\n\n")
                        os.remove(path + '\\psexec_results\\services_registry' + today + '.txt')
                    else:
                        self.output.insert('end', "Found PSEXESVC inside Services or AppCompatCache! Please check the map: psexec_results.\n\n")
                except FileNotFoundError:
                    self.output.insert('end', "Did not find PSEXESVC inside Services or AppCompatCache\n\n")
                    self.mainframe.update_idletasks()


            if self.option_WMI.get() == True:
                self.output.insert('end', "SCANNING FOR POTENTIALLY MALICIOUS USE OF WMI USING DI COLLECTION\n\n")
                # AppCompatCache
                w.wmi_system()
                self.output.insert('end', "Looking for malicious indicators inside AppCompatCache \n")
                self.mainframe.update_idletasks()
                if os.stat(path + '\\wmi_results\\registry' + today + '.txt').st_size == 0:
                    self.output.insert('end', "Did not find malicious indicators inside AppCompatCache\n\n")
                else:
                    self.output.insert('end', "Found malicious indicators inside AppCompatCache! Please check registry" + today + ".txt in the map wmi_results.\n\n")
                self.mainframe.update_idletasks()

                # Amcache
                self.output.insert('end', "Looking for malicious indicators inside Amcache \n")
                self.mainframe.update_idletasks()
                # w.wmi_amcache()
                if os.stat(path + '\\wmi_results\\registry' + today + '.txt').st_size == 0:
                    self.output.insert('end', "Did not find malicious indicators inside Amcache \n\n")
                else:
                    self.output.insert('end', "Found malicious indicators inside AppCompatCache! Please check registry" + today + ".txt in the map wmi_results.\n\n")
                    self.mainframe.update_idletasks()

                # Prefetch
                self.output.insert('end', "Looking for malicious indicators inside Prefetch \n")
                self.mainframe.update_idletasks()
                w.wmi_prefetch()
                if os.stat(path + '\\wmi_results\\filesystem' + today + '.txt').st_size == 0:
                    self.output.insert('end', "Did not find malicious indicators inside Prefetch \n\n")
                else:
                    self.output.insert('end', "Found malicious indicators inside Prefetch! Please check the map: wmi_results.\n\n")
                    self.mainframe.update_idletasks()

                
                # MFT
                # self.output.insert('end', "Looking for malicious indicators inside MFT \n")
                # self.mainframe.update_idletasks()
                # w.wmi_filesystem()
                # if os.stat(path + '\\wmi_results\\MFT' + today + '.txt').st_size == 0:
                #     self.output.insert('end', "Did not find malicious indicators inside MFT \n\n")
                # else:
                #     self.output.insert('end', "Found malicious indicators inside MFT! Please check the map: wmi_results.\n\n")
                #     self.mainframe.update_idletasks()


            if self.option_Cred.get() == True:
                if self.folder_lbl_cred != None:
                    self.output.insert('end', "SCANNING FOR POTENTIAL CREDENTIAL DUMPING USING DI COLLECTION\n\n")
                    self.mainframe.update_idletasks()
                    output = c.get_matches()
                    try:
                        if os.stat(path + '\\credential_dump_results\\credential_dump_results' + today + '.json').st_size == 0:
                            self.output.insert('end', "No indication of Credential Dumping found\n\n")
                        else:
                            self.output.insert('end', "Results can be found in 'credential_dump_results.json'\n\n")
                            for pair in output.items():
                                self.output.insert('end', "Found indications of " + str(pair[1]) + " in the file " + str(pair[0]) + '\n\n')
                    except FileNotFoundError:
                        self.output.insert('end', "No indication of Credential Dumping found\n\n")
                    self.mainframe.update_idletasks()
                    
                else:
                    self.output.insert('end', "Please select a folder to analyse for credential dumping\n\n")
                    self.mainframe.update_idletasks()
                    return
                
    
        self.output.insert('end', "Done!\n")
        self.mainframe.update_idletasks()

        self.output['state'] = 'disabled'

root = Tk()
CollectAndAnalyse(root)
root.mainloop()
