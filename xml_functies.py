import lxml.etree
import Evtx.Evtx as evtx
import xml.etree.cElementTree as ET


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    '''Getting to the EventID section.'''
    return node.find("%s%s" % (ns, tag))

root = ET.Element('root')
tree = ET.ElementTree(root)


#SYSTEM
def xml_7040(System, path, map, today):
    '''Retrieving Windows System EventID 7040 and converting the result to xml.'''
    count = 0
    with evtx.Evtx(System) as log:
        for record in log.records():
            try:
                node = record.lxml()
            except lxml.etree.XMLSyntaxError:
                continue
            except OSError:
                continue

            if get_child(get_child(node, 'System'), 'EventID').text:
                if int(get_child(get_child(node, 'System'), 'EventID').text) == 7040:
                    count += 1

                    Event = ET.Element('Event')
                    system = ET.SubElement(Event, "system")

                    for x in get_child(node, 'System').getchildren():
                        if x.get('Name') and x.get('Guid') and x.get('EventSourceName'):
                            ET.SubElement(system, "Provider", Name=x.get('Name'), Guid=x.get('Guid'),
                                          EventSourceName=x.get('EventSourceName')).text = ''

                    for x in get_child(node, 'System').getchildren():
                        if x.get('Qualifiers'):
                            ET.SubElement(system, "EventID", Qualifiers=x.get('Qualifiers')).text = str(
                                get_child(get_child(node, 'System'), 'EventID').text)

                    ET.SubElement(system, "Version").text = str(get_child(get_child(node, 'System'), 'Version').text)
                    ET.SubElement(system, "Level").text = str(get_child(get_child(node, 'System'), 'Level').text)
                    ET.SubElement(system, "Task").text = str(get_child(get_child(node, 'System'), 'Task').text)
                    ET.SubElement(system, "Opcode").text = str(get_child(get_child(node, 'System'), 'Opcode').text)
                    ET.SubElement(system, "Keywords").text = str(get_child(get_child(node, 'System'), 'Keywords').text)
                    for x in get_child(node, 'System').getchildren():
                        if x.get('SystemTime'):
                            ET.SubElement(system, "TimeCreated", SystemTime=x.get('SystemTime')).text = ''
                    ET.SubElement(system, "EventRecordID").text = str(
                        get_child(get_child(node, 'System'), 'EventRecordID').text)
                    ET.SubElement(system, "Correlation").text = str(
                        get_child(get_child(node, 'System'), 'Correlation').text)

                    for x in get_child(node, 'System').getchildren():
                        if x.get('ProcessID') and x.get('ThreadID'):
                            ET.SubElement(system, "Execution", ProcessID=x.get('ProcessID'),
                                          ThreadID=x.get('ThreadID')).text = ''
                    ET.SubElement(system, "Channel").text = str(get_child(get_child(node, 'System'), 'Channel').text)
                    ET.SubElement(system, "Computer").text = str(get_child(get_child(node, 'System'), 'Computer').text)
                    for x in get_child(node, 'System').getchildren():
                        if x.get('UserID'):
                            ET.SubElement(system, "Security", UserID=x.get('UserID')).text = ''

                    EventData = ET.SubElement(Event, "EventData")
                    for eventDataChild in get_child(node, 'EventData').getchildren():
                        nameValue = eventDataChild.values()[0]
                        ET.SubElement(EventData, "Data", Name=nameValue).text = eventDataChild.text

                    root.append(Event)

                    if path == ".//":
                        filepathxml = str(path + map + "//" + 'xml_7040_' + today + '.xml')
                    else:
                        filepathxml = str(path + "//" + map + "//" + 'xml_7040_' + today + '.xml')

                    tree.write(filepathxml)

    result = 'Results eventID 7040: ' + str(count)
    return result

def xml_7045(System, path, map, today):
    '''Retrieving Windows System EventID 7045 and converting the result to xml.'''
    count = 0
    with evtx.Evtx(System) as log:
        for record in log.records():
            try:
                node = record.lxml()
            except lxml.etree.XMLSyntaxError:
                continue
            except OSError:
                continue

            if get_child(get_child(node, 'System'), 'EventID').text:
                if int(get_child(get_child(node, 'System'), 'EventID').text) == 7045:
                    count += 1

                    Event = ET.Element('Event')
                    system = ET.SubElement(Event, "system")

                    for x in get_child(node, 'System').getchildren():
                        if x.get('Name') and x.get('Guid') and x.get('EventSourceName'):
                            ET.SubElement(system, "Provider", Name=x.get('Name'), Guid=x.get('Guid'),
                                          EventSourceName=x.get('EventSourceName')).text = ''
                    for x in get_child(node, 'System').getchildren():
                        if x.get('Qualifiers'):
                            ET.SubElement(system, "EventID", Qualifiers=x.get('Qualifiers')).text = str(
                                get_child(get_child(node, 'System'), 'EventID').text)
                    ET.SubElement(system, "Version").text = str(get_child(get_child(node, 'System'), 'Version').text)
                    ET.SubElement(system, "Level").text = str(get_child(get_child(node, 'System'), 'Level').text)
                    ET.SubElement(system, "Task").text = str(get_child(get_child(node, 'System'), 'Task').text)
                    ET.SubElement(system, "Opcode").text = str(get_child(get_child(node, 'System'), 'Opcode').text)
                    ET.SubElement(system, "Keywords").text = str(get_child(get_child(node, 'System'), 'Keywords').text)
                    for x in get_child(node, 'System').getchildren():
                        if x.get('SystemTime'):
                            ET.SubElement(system, "TimeCreated", SystemTime=x.get('SystemTime')).text = ''
                    ET.SubElement(system, "EventRecordID").text = str(
                        get_child(get_child(node, 'System'), 'EventRecordID').text)
                    ET.SubElement(system, "Correlation").text = str(
                        get_child(get_child(node, 'System'), 'Correlation').text)

                    for x in get_child(node, 'System').getchildren():
                        if x.get('ProcessID') and x.get('ThreadID'):
                            ET.SubElement(system, "Execution", ProcessID=x.get('ProcessID'),
                                          ThreadID=x.get('ThreadID')).text = ''
                    ET.SubElement(system, "Channel").text = str(get_child(get_child(node, 'System'), 'Channel').text)
                    ET.SubElement(system, "Computer").text = str(get_child(get_child(node, 'System'), 'Computer').text)
                    for x in get_child(node, 'System').getchildren():
                        if x.get('UserID'):
                            ET.SubElement(system, "Security", UserID=x.get('UserID')).text = ''

                    EventData = ET.SubElement(Event, "EventData")
                    for eventDataChild in get_child(node, 'EventData').getchildren():
                        nameValue = eventDataChild.values()[0]
                        ET.SubElement(EventData, "Data", Name=nameValue).text = eventDataChild.text

                    root.append(Event)

                    if path == ".//":
                        filepathxml = str(path + map + "//" + 'xml_7045_' + today + '.xml')
                    else:
                        filepathxml = str(path + "//" + map + "//" + 'xml_7045_' + today + '.xml')

                    tree.write(filepathxml)

    result = 'Results eventID 7045: ' + str(count)
    return result

#PowerShell-Operational
def xml_4104(WinPowerShellO, path, map, today):
    '''Retrieving Windows PowerShell Operational EventID 4104 and converting the result to xml.'''
    count = 0
    with evtx.Evtx(WinPowerShellO) as log:
        for record in log.records():
            try:
                node = record.lxml()
            except lxml.etree.XMLSyntaxError:
                continue

            if int(get_child(get_child(node, 'System'), 'EventID').text) == 4104:
                count += 1


                Event = ET.Element('Event')
                system = ET.SubElement(Event, "system")

                for x in get_child(node, 'System').getchildren():
                    if x.get('Name') and x.get('Guid'):
                        ET.SubElement(system, "Provider", Name=x.get('Name'), Guid=x.get('Guid')).text = ''

                ET.SubElement(system, "EventID").text = str(get_child(get_child(node, 'System'), 'EventID').text)
                ET.SubElement(system, "Version").text = str(get_child(get_child(node, 'System'), 'Version').text)
                ET.SubElement(system, "Level").text = str(get_child(get_child(node, 'System'), 'Level').text)
                ET.SubElement(system, "Task").text = str(get_child(get_child(node, 'System'), 'Task').text)
                ET.SubElement(system, "Opcode").text = str(get_child(get_child(node, 'System'), 'Opcode').text)
                ET.SubElement(system, "Keywords").text = str(get_child(get_child(node, 'System'), 'Keywords').text)

                for x in get_child(node, 'System').getchildren():
                    if x.get('SystemTime'):
                        ET.SubElement(system, "TimeCreated", SystemTime=x.get('SystemTime')).text = ''

                ET.SubElement(system, "EventRecordID").text = str(
                    get_child(get_child(node, 'System'), 'EventRecordID').text)

                for x in get_child(node, 'System').getchildren():
                    if x.get('ActivityID'):
                        ET.SubElement(system, "Correlation", ActivityID=x.get('ActivityID')).text = ''

                for x in get_child(node, 'System').getchildren():
                    if x.get('ProcessID') and x.get('ThreadID'):
                        ET.SubElement(system, "Execution", ProcessID=x.get('ProcessID'),
                                      ThreadID=x.get('ThreadID')).text = ''

                ET.SubElement(system, "Channel").text = str(get_child(get_child(node, 'System'), 'Channel').text)
                ET.SubElement(system, "Computer").text = str(get_child(get_child(node, 'System'), 'Computer').text)

                for x in get_child(node, 'System').getchildren():
                    if x.get('UserID'):
                        ET.SubElement(system, "Security", UserID=x.get('UserID')).text = ''

                EventData = ET.SubElement(Event, "EventData")
                for eventDataChild in get_child(node, 'EventData').getchildren():
                    nameValue = eventDataChild.values()[0]
                    ET.SubElement(EventData, "Data", Name=nameValue).text = eventDataChild.text


                root.append(Event)

                if path == ".//":
                    filepathxml = str(path + map + "//" + 'xml_4104_' + today + '.xml')
                else:
                    filepathxml = str(path + "//" + map + "//" + 'xml_4104_' + today + '.xml')

                tree.write(filepathxml)
    result = 'Results eventID 4104: ' + str(count)
    return result

def xml_53504(WinPowerShellO, path, map, today):
    '''Retrieving Windows PowerShell Operational EventID 53504 and converting the result to xml.'''
    count = 0
    with evtx.Evtx(WinPowerShellO) as log:
        for record in log.records():
            try:
                node = record.lxml()
            except lxml.etree.XMLSyntaxError:
                continue

            if int(get_child(get_child(node, 'System'), 'EventID').text) == 53504:
                count += 1


                Event = ET.Element('Event')
                system = ET.SubElement(Event, "system")

                for x in get_child(node, 'System').getchildren():
                    if x.get('Name') and x.get('Guid'):
                        ET.SubElement(system, "Provider", Name=x.get('Name'), Guid=x.get('Guid')).text = ''

                ET.SubElement(system, "EventID").text = str(get_child(get_child(node, 'System'), 'EventID').text)
                ET.SubElement(system, "Version").text = str(get_child(get_child(node, 'System'), 'Version').text)
                ET.SubElement(system, "Level").text = str(get_child(get_child(node, 'System'), 'Level').text)
                ET.SubElement(system, "Task").text = str(get_child(get_child(node, 'System'), 'Task').text)
                ET.SubElement(system, "Opcode").text = str(get_child(get_child(node, 'System'), 'Opcode').text)
                ET.SubElement(system, "Keywords").text = str(get_child(get_child(node, 'System'), 'Keywords').text)

                for x in get_child(node, 'System').getchildren():
                    if x.get('SystemTime'):
                        ET.SubElement(system, "TimeCreated", SystemTime=x.get('SystemTime')).text = ''

                ET.SubElement(system, "EventRecordID").text = str(
                    get_child(get_child(node, 'System'), 'EventRecordID').text)

                for x in get_child(node, 'System').getchildren():
                    if x.get('ActivityID'):
                        ET.SubElement(system, "Correlation", ActivityID=x.get('ActivityID')).text = ''

                for x in get_child(node, 'System').getchildren():
                    if x.get('ProcessID') and x.get('ThreadID'):
                        ET.SubElement(system, "Execution", ProcessID=x.get('ProcessID'),
                                      ThreadID=x.get('ThreadID')).text = ''

                ET.SubElement(system, "Channel").text = str(get_child(get_child(node, 'System'), 'Channel').text)
                ET.SubElement(system, "Computer").text = str(get_child(get_child(node, 'System'), 'Computer').text)

                for x in get_child(node, 'System').getchildren():
                    if x.get('UserID'):
                        ET.SubElement(system, "Security", UserID=x.get('UserID')).text = ''

                EventData = ET.SubElement(Event, "EventData")
                for eventDataChild in get_child(node, 'EventData').getchildren():
                    nameValue = eventDataChild.values()[0]
                    ET.SubElement(EventData, "Data", Name=nameValue).text = eventDataChild.text


                root.append(Event)

                if path == ".//":
                    filepathxml = str(path + map + "//" + 'xml_53504_' + today + '.xml')
                else:
                    filepathxml = str(path + "//" + map + "//" + 'xml_53504_' + today + '.xml')

                tree.write(filepathxml)
    result = 'Results eventID 53504: ' + str(count)
    return result
