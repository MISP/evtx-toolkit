#!/usr/bin/env python3

import Evtx.Evtx as evtx
import Evtx.Views as e_views
import datetime
import json

def getpath(path=None):
    if path is None:
        return False
    image = path.split("\\")[-1]
    d = "\\".join(path.split("\\")[:-1])
    if not d:
        d = "\\"
    if not image:
        image = None
    return (d, image)

def parse_record(record=None, epochconvert=True):
    if record is None:
        return False
    temp = {}
    for node in record:
        parent = node.tag.split("}")[-1]
        for child in node:
            if parent == "EventData":
                event_data_type = child.attrib["Name"]
                temp["{}_{}".format(parent, event_data_type)] = child.text
            else:
                child_name = child.tag.split("}")[-1]
                if child.attrib:
                    for key, value in child.attrib.items():
                        temp["{}_{}".format(child_name, key)] = value
                    temp[child_name] = child.text
                else:
                    temp[child_name] = child.text
    # time to epoch
    timekeys = ["EventData_UtcTime", "TimeCreated_SystemTime"]
    if epochconvert:
        for tkey in timekeys:
            if tkey in temp:
                try:
                    time = datetime.datetime.strptime(temp[tkey], "%Y-%m-%d %H:%M:%S.%f")
                except:
                    time = datetime.datetime.strptime(temp[tkey], "%Y-%m-%d %H:%M:%S")
                temp[tkey] = int(time.strftime("%s"))
    return temp

def graphout(record=None):
    if record is None:
        return False
    temp = []
    if 'EventData_ProcessGuid' in record:
        node = {}
        node['type'] = "node"
        node['value'] = record['EventData_ProcessGuid']
        node['label'] = "ProcessGuid"
        temp.append(node)
    if 'EventData_Image' in record:
        node = {}
        node['type'] = "node"
        node['value'] = record['EventData_Image']
        node['label'] = "Image"
        temp.append(node)
    if 'EventData_CommandLine' in record:
        node = {}
        node['type'] = "node"
        node['value'] = record['EventData_CommandLine']
        node['label'] = 'CommandLine'
        temp.append(node)
    if 'EventData_ParentProcessGuid' in record:
        edge = {}
        edge['type'] = "edge"
        edge['relationship'] = "child-of"
        edge['source'] = record['EventData_ProcessGuid']
        edge['destination'] = record['EventData_ParentProcessGuid']
        edge['label'] = 'ParentProcessGuid'
        temp.append(edge)
    if 'EventData_ParentProcessId' in record:
        edge = {}
        edge['type'] = "edge"
        edge['relationship'] = "child-of"
        edge['source'] = record['EventData_ProcessId']
        edge['destination'] = record['EventData_ParentProcessId']
        edge['label'] = 'ParentProcessId'
        temp.append(edge)
    if 'EventData_ParentImage' in record:
        edge = {}
        edge['type'] = "edge"
        edge['relationship'] = "child-of"
        edge['source'] = record['EventData_Image']
        edge['destination'] = record['EventData_ParentImage']
        edge['label'] = 'ParentImage'
        temp.append(edge)
    if 'EventData_ParentCommandLine' in record:
        edge = {}
        edge['type'] = "edge"
        edge['relationship'] = "child-of"
        edge['source'] = record['EventData_ProcessGuid']
        edge['destination'] = record['EventData_ParentCommandLine']
        edge['label'] = 'ParentCommandLine'
        temp.append(edge)

    ### Sysmon
    if 'EventData_DestinationIp' in record:
        edge = {}
        edge['type'] = "edge"
        edge['relationship'] = "connects-to"
        edge['source'] = record['EventData_ProcessGuid']
        edge['destination'] = "{}://{}:{}".format(record['EventData_Protocol'], record['EventData_DestinationIp'], record['EventData_DestinationPort'])
        edge['label'] = 'DestinationIp'
        temp.append(edge)

    if 'EventData_TargetFilename' in record:
        edge = {}
        edge['type'] = "edge"
        edge['relationship'] = "creates"
        edge['source'] = record['EventData_ProcessGuid']
        (directory, image) = getpath(record['EventData_TargetFilename'])
        print (directory)
        edge['destination'] = record['EventData_TargetFilename']
        temp.append(edge)

    return temp

def main():
    import argparse

    parser = argparse.ArgumentParser(description="EVTX file to JSON/graph/MISP Objects")
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX event log file to dump")
    parser.add_argument("--verbose", default=False, help="Verbose output (debugging)", action='store_true')
    parser.add_argument("--noepochconvert", default=False, help="Disable time to epoch conversion", action='store_true')
    parser.add_argument('-o', help="output format (json, graph)", default="json")
    parser.add_argument("--dump-hashes", default=False, help="Dump EventData - Hashes", action='store_true')
    args = parser.parse_args()
    if args.noepochconvert:
        epochconvert = False
    else:
        epochconvert = True

    with evtx.Evtx(args.evtx) as log:
        if args.verbose:
            print(e_views.XML_HEADER)
            print("<Events>")
        for record in log.records():
            if args.verbose:
                print(record.xml())
            parsed_rec = parse_record(record=record.lxml(), epochconvert=epochconvert)
            if args.o == 'json' and not args.dump_hashes:
                print(json.dumps(parsed_rec))
            if args.o == 'graph':
                print(json.dumps(graphout(record=parsed_rec)))
            if args.dump_hashes:
                if 'EventData_Hashes' in parsed_rec:
                    print(parsed_rec['EventData_Hashes'])
        if args.verbose:
            print("</Events>")


if __name__ == "__main__":
    main()
