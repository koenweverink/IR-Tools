from xml.etree import ElementTree
import csv


#SYSTEM
def csv_7040(path, map, today):
    '''Retrieving Windows System EventID 7040 and converting the result to csv.'''
    if path == ".//":
        filepathxml = str(path + map + "//" + 'xml_7040_' + today + '.xml')
    else:
        filepathxml = str(path + "//" + map + "//" + 'xml_7040_' + today + '.xml')

    tree = ElementTree.parse(filepathxml)
    tree.findall('.//system')

    if path == ".//":
        filepathcsv = str(path + map + "//" + 'csv_7040_' + today + '.csv')
    else:
        filepathcsv = str(path + "//" + map + "//" + 'csv_7040_' + today + '.csv')

    with open(filepathcsv, 'w', newline='') as csvfile:
        fieldnames = ['Provider Name', 'Provider Guid', 'Provider EventSourceName', 'EventID Qualifiers', 'EventID',
                      'Level', 'Task', 'Opcode', 'Keywords', 'TimeCreated SystemTime', 'EventRecordID',
                      'Execution ProcessID', 'Execution ThreadID', 'Channel', 'Computer', 'Security UserID', 'param1',
                      'param2', 'param3', 'param4']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in tree.findall('.//Event'):

            SystemProvider = item.findall('system/Provider')
            for x in SystemProvider:
                Provider_Name = x.get('Name')
                Provider_Guid = x.get('Guid')
                Provider_EventSourceName = x.get('EventSourceName')

            SystemEventID = item.findall('system/EventID')
            for x in SystemEventID:
                EventID_Qualifiers = x.get('Qualifiers')

            SystemTimeCreated = item.findall('system/TimeCreated')
            for x in SystemTimeCreated:
                TimeCreated_SystemTime = x.get('SystemTime')

            SystemSecurity = item.findall('system/Security')
            for x in SystemSecurity:
                Security_UserID = x.get('UserID')

            SystemExecution = item.findall('system/Execution')
            for x in SystemExecution:
                Execution_ProcessID = x.get('ProcessID')
                Execution_ThreadID = x.get('ThreadID')

            eventDataChild = item.findall('EventData/Data')
            dataDictionary = dict()
            for value in eventDataChild:
                dataDictionary[value.get('Name')] = value.text

            writer.writerow({
                'Provider Name': Provider_Name,
                'Provider Guid': Provider_Guid,
                'Provider EventSourceName': Provider_EventSourceName,
                'EventID Qualifiers': EventID_Qualifiers,
                'EventID': item.find('system').find('EventID').text,
                'Level': item.find('system').find('Level').text,
                'Task': item.find('system').find('Task').text,
                'Opcode': item.find('system').find('Opcode').text,
                'Keywords': item.find('system').find('Keywords').text,
                'TimeCreated SystemTime': TimeCreated_SystemTime,
                'EventRecordID': item.find('system').find('EventRecordID').text,
                'Execution ProcessID': Execution_ProcessID,
                'Execution ThreadID': Execution_ThreadID,
                'Channel': item.find('system').find('Channel').text,
                'Computer': item.find('system').find('Computer').text,
                'Security UserID': Security_UserID,

                'param1': dataDictionary.get('param1'),
                'param2': dataDictionary.get('param2'),
                'param3': dataDictionary.get('param3'),
                'param4': dataDictionary.get('param4')
            })


def csv_7045(path, map, today):
    '''Retrieving Windows System EventID 7045 and converting the result to csv.'''
    if path == ".//":
        filepathxml = str(path + map + "//" + 'xml_7045_' + today + '.xml')
    else:
        filepathxml = str(path + "//" + map + "//" + 'xml_7045_' + today + '.xml')

    tree = ElementTree.parse(filepathxml)
    tree.findall('.//system')

    if path == ".//":
        filepathcsv = str(path + map + "//" + 'csv_7045_' + today + '.csv')
    else:
        filepathcsv = str(path + "//" + map + "//" + 'csv_7045_' + today + '.csv')

    with open(filepathcsv, 'w', newline='') as csvfile:
        fieldnames = ['Provider Name', 'Provider Guid', 'Provider EventSourceName', 'EventID Qualifiers', 'EventID',
                      'Level', 'Task', 'Opcode', 'Keywords', 'TimeCreated SystemTime', 'EventRecordID',
                      'Execution ProcessID', 'Execution ThreadID', 'Channel', 'Computer', 'Security UserID',
                      'ServiceName', 'ImagePath', 'ServiceType', 'StartType', 'AccountName']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in tree.findall('.//Event'):

            SystemProvider = item.findall('system/Provider')
            for x in SystemProvider:
                Provider_Name = x.get('Name')
                Provider_Guid = x.get('Guid')
                Provider_EventSourceName = x.get('EventSourceName')

            SystemEventID = item.findall('system/EventID')
            for x in SystemEventID:
                EventID_Qualifiers = x.get('Qualifiers')

            SystemTimeCreated = item.findall('system/TimeCreated')
            for x in SystemTimeCreated:
                TimeCreated_SystemTime = x.get('SystemTime')

            SystemSecurity = item.findall('system/Security')
            for x in SystemSecurity:
                Security_UserID = x.get('UserID')

            SystemExecution = item.findall('system/Execution')
            for x in SystemExecution:
                Execution_ProcessID = x.get('ProcessID')
                Execution_ThreadID = x.get('ThreadID')

            eventDataChild = item.findall('EventData/Data')
            dataDictionary = dict()
            for value in eventDataChild:
                dataDictionary[value.get('Name')] = value.text

            writer.writerow({
                'Provider Name': Provider_Name,
                'Provider Guid': Provider_Guid,
                'Provider EventSourceName': Provider_EventSourceName,
                'EventID Qualifiers': EventID_Qualifiers,
                'EventID': item.find('system').find('EventID').text,
                'Level': item.find('system').find('Level').text,
                'Task': item.find('system').find('Task').text,
                'Opcode': item.find('system').find('Opcode').text,
                'Keywords': item.find('system').find('Keywords').text,
                'TimeCreated SystemTime': TimeCreated_SystemTime,
                'EventRecordID': item.find('system').find('EventRecordID').text,
                'Execution ProcessID': Execution_ProcessID,
                'Execution ThreadID': Execution_ThreadID,
                'Channel': item.find('system').find('Channel').text,
                'Computer': item.find('system').find('Computer').text,
                'Security UserID': Security_UserID,

                'ServiceName': dataDictionary.get('ServiceName'),
                'ImagePath': dataDictionary.get('ImagePath'),
                'ServiceType': dataDictionary.get('ServiceType'),
                'StartType': dataDictionary.get('StartType'),
                'AccountName': dataDictionary.get('AccountName')
            })

#POWERSHELL-OPERATION
def csv_4104(path, map, today):
    '''Retrieving Windows PowerShell Operational EventID 4104 and converting the result to csv.'''
    if path == ".//":
        filepathxml = str(path + map + "//" + 'xml_4104_' + today + '.xml')
    else:
        filepathxml = str(path + "//" + map + "//" + 'xml_4104_' + today + '.xml')

    tree = ElementTree.parse(filepathxml)
    tree.findall('.//system')

    if path == ".//":
        filepathcsv = str(path + map + "//" + 'csv_4104_' + today + '.csv')
    else:
        filepathcsv = str(path + "//" + map + "//" + 'csv_4104_' + today + '.csv')

    with open(filepathcsv, 'w', newline='') as csvfile:
        fieldnames = ['Provider Name', 'Provider Guid', 'EventID', 'Level', 'Task', 'Opcode', 'Keywords',
                      'TimeCreated SystemTime', 'EventRecordID', 'Correlation ActivityID', 'Execution ProcessID',
                      'Execution ThreadID', 'Channel', 'Computer', 'Security UserID', 'MessageNumber', 'MessageTotal',
                      'ScriptBlockText', 'ScriptBlockId', 'Path']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in tree.findall('.//Event'):

            SystemProvider = item.findall('system/Provider')
            for x in SystemProvider:
                Provider_Name = x.get('Name')
                Provider_Guid = x.get('Guid')

            SystemTimeCreated = item.findall('system/TimeCreated')
            for x in SystemTimeCreated:
                TimeCreated_SystemTime = x.get('SystemTime')

            SystemCorrelation = item.findall('system/Correlation')
            for x in SystemCorrelation:
                Correlation_ActivityID = x.get('ActivityID')

            SystemSecurity = item.findall('system/Security')
            for x in SystemSecurity:
                Security_UserID = x.get('UserID')

            SystemExecution = item.findall('system/Execution')
            for x in SystemExecution:
                Execution_ProcessID = x.get('ProcessID')
                Execution_ThreadID = x.get('ThreadID')

            eventDataChild = item.findall('EventData/Data')
            dataDictionary = dict()
            for value in eventDataChild:
                dataDictionary[value.get('Name')] = value.text

            writer.writerow({
                'Provider Name': Provider_Name,
                'Provider Guid': Provider_Guid,
                'EventID': item.find('system').find('EventID').text,
                'Level': item.find('system').find('Level').text,
                'Task': item.find('system').find('Task').text,
                'Opcode': item.find('system').find('Opcode').text,
                'Keywords': item.find('system').find('Keywords').text,
                'TimeCreated SystemTime': TimeCreated_SystemTime,
                'EventRecordID': item.find('system').find('EventRecordID').text,
                'Correlation ActivityID': Correlation_ActivityID,
                'Execution ProcessID': Execution_ProcessID,
                'Execution ThreadID': Execution_ThreadID,
                'Channel': item.find('system').find('Channel').text,
                'Computer': item.find('system').find('Computer').text,
                'Security UserID': Security_UserID,

                'MessageNumber': dataDictionary.get('MessageNumber'),
                'MessageTotal': dataDictionary.get('MessageTotal'),
                'ScriptBlockText': dataDictionary.get('ScriptBlockText'),
                'ScriptBlockId': dataDictionary.get('ScriptBlockId'),
                'Path': dataDictionary.get('Path')
            })

def csv_53504(path, map, today):
    '''Retrieving Windows PowerShell Operational EventID 53504 and converting the result to csv.'''
    if path == ".//":
        filepathxml = str(path + map + "//" + 'xml_53504_' + today + '.xml')
    else:
        filepathxml = str(path + "//" + map + "//" + 'xml_53504_' + today + '.xml')

    tree = ElementTree.parse(filepathxml)
    tree.findall('.//system')

    if path == ".//":
        filepathcsv = str(path + map + "//" + 'csv_53504_' + today + '.csv')
    else:
        filepathcsv = str(path + "//" + map + "//" + 'csv_53504_' + today + '.csv')

    with open(filepathcsv, 'w', newline='') as csvfile:
        fieldnames = ['Provider Name', 'Provider Guid', 'EventID', 'Level', 'Task', 'Opcode', 'Keywords',
                      'TimeCreated SystemTime', 'EventRecordID', 'Correlation ActivityID', 'Execution ProcessID',
                      'Execution ThreadID', 'Channel', 'Computer', 'Security UserID', 'param1', 'param2']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in tree.findall('.//Event'):

            SystemProvider = item.findall('system/Provider')
            for x in SystemProvider:
                Provider_Name = x.get('Name')
                Provider_Guid = x.get('Guid')

            SystemTimeCreated = item.findall('system/TimeCreated')
            for x in SystemTimeCreated:
                TimeCreated_SystemTime = x.get('SystemTime')

            SystemCorrelation = item.findall('system/Correlation')
            for x in SystemCorrelation:
                Correlation_ActivityID = x.get('ActivityID')

            SystemSecurity = item.findall('system/Security')
            for x in SystemSecurity:
                Security_UserID = x.get('UserID')

            SystemExecution = item.findall('system/Execution')
            for x in SystemExecution:
                Execution_ProcessID = x.get('ProcessID')
                Execution_ThreadID = x.get('ThreadID')

            eventDataChild = item.findall('EventData/Data')
            dataDictionary = dict()
            for value in eventDataChild:
                dataDictionary[value.get('Name')] = value.text

            writer.writerow({
                'Provider Name': Provider_Name,
                'Provider Guid': Provider_Guid,
                'EventID': item.find('system').find('EventID').text,
                'Level': item.find('system').find('Level').text,
                'Task': item.find('system').find('Task').text,
                'Opcode': item.find('system').find('Opcode').text,
                'Keywords': item.find('system').find('Keywords').text,
                'TimeCreated SystemTime': TimeCreated_SystemTime,
                'EventRecordID': item.find('system').find('EventRecordID').text,
                'Correlation ActivityID': Correlation_ActivityID,
                'Execution ProcessID': Execution_ProcessID,
                'Execution ThreadID': Execution_ThreadID,
                'Channel': item.find('system').find('Channel').text,
                'Computer': item.find('system').find('Computer').text,
                'Security UserID': Security_UserID,

                'param1': dataDictionary.get('param1'),
                'param2': dataDictionary.get('param2')
            })
