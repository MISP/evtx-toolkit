# evtx-toolkit (WiP)

Tool to read EVTX files including SYSMON and convert to JSON, MISP Objects and Graph stream

# Usage

~~~~shell
usage: evtx_dump.py [-h] [--verbose] [--noepochconvert] [-o O] [--dump-hashes]
                    evtx

EVTX file to JSON/graph/MISP Objects

positional arguments:
  evtx              Path to the Windows EVTX event log file to dump

optional arguments:
  -h, --help        show this help message and exit
  --verbose         Verbose output (debugging)
  --noepochconvert  Disable time to epoch conversion
  -o O              output format (json, graph)
  --dump-hashes     Dump EventData - Hashes
~~~~

# Sample

~~~~json
adulau@dobbertin:~/git/evtx-toolkit$ python3 bin/evtx_dump.py samples/EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_ftp.evtx  -o graph  | jq . 
[
  {
    "type": "node",
    "value": "{365abb72-55c1-5cd8-0000-0010970d2f00}",
    "label": "ProcessGuid"
  },
  {
    "type": "node",
    "value": "C:\\Windows\\System32\\cmd.exe",
    "label": "Image"
  },
  {
    "type": "node",
    "value": "\"C:\\Windows\\system32\\cmd.exe\" ",
    "label": "CommandLine"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55c1-5cd8-0000-0010970d2f00}",
    "destination": "{365abb72-502e-5cd8-0000-00102a330700}",
    "label": "ParentProcessGuid"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "4092",
    "destination": "3192",
    "label": "ParentProcessId"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "C:\\Windows\\System32\\cmd.exe",
    "destination": "C:\\Windows\\explorer.exe",
    "label": "ParentImage"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55c1-5cd8-0000-0010970d2f00}",
    "destination": "C:\\Windows\\Explorer.EXE",
    "label": "ParentCommandLine"
  }
]
[
  {
    "type": "node",
    "value": "{365abb72-55df-5cd8-0000-001018532f00}",
    "label": "ProcessGuid"
  },
  {
    "type": "node",
    "value": "C:\\Python27\\python.exe",
    "label": "Image"
  },
  {
    "type": "node",
    "value": "python  winpwnage.py -u execute -i 11 -p c:\\Windows\\system32\\calc.exe",
    "label": "CommandLine"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55df-5cd8-0000-001018532f00}",
    "destination": "{365abb72-55c1-5cd8-0000-0010970d2f00}",
    "label": "ParentProcessGuid"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "956",
    "destination": "4092",
    "label": "ParentProcessId"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "C:\\Python27\\python.exe",
    "destination": "C:\\Windows\\System32\\cmd.exe",
    "label": "ParentImage"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55df-5cd8-0000-001018532f00}",
    "destination": "\"C:\\Windows\\system32\\cmd.exe\" ",
    "label": "ParentCommandLine"
  }
]
[
  {
    "type": "node",
    "value": "{365abb72-55f1-5cd8-0000-0010781c3300}",
    "label": "ProcessGuid"
  },
  {
    "type": "node",
    "value": "C:\\Windows\\System32\\cmd.exe",
    "label": "Image"
  },
  {
    "type": "node",
    "value": "C:\\Windows\\system32\\cmd.exe /C c:\\Windows\\system32\\calc.exe",
    "label": "CommandLine"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55f1-5cd8-0000-0010781c3300}",
    "destination": "{365abb72-55f1-5cd8-0000-00108a153300}",
    "label": "ParentProcessGuid"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "2392",
    "destination": "3668",
    "label": "ParentProcessId"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "C:\\Windows\\System32\\cmd.exe",
    "destination": "C:\\Windows\\System32\\ftp.exe",
    "label": "ParentImage"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55f1-5cd8-0000-0010781c3300}",
    "destination": "\"C:\\Windows\\System32\\ftp.exe\" -s:c:\\users\\ieuser\\appdata\\local\\temp\\ftp.txt",
    "label": "ParentCommandLine"
  }
]
[
  {
    "type": "node",
    "value": "{365abb72-55f1-5cd8-0000-00103d1e3300}",
    "label": "ProcessGuid"
  },
  {
    "type": "node",
    "value": "C:\\Windows\\System32\\calc.exe",
    "label": "Image"
  },
  {
    "type": "node",
    "value": "c:\\Windows\\system32\\calc.exe",
    "label": "CommandLine"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55f1-5cd8-0000-00103d1e3300}",
    "destination": "{365abb72-55f1-5cd8-0000-0010781c3300}",
    "label": "ParentProcessGuid"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "684",
    "destination": "2392",
    "label": "ParentProcessId"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "C:\\Windows\\System32\\calc.exe",
    "destination": "C:\\Windows\\System32\\cmd.exe",
    "label": "ParentImage"
  },
  {
    "type": "edge",
    "relationship": "child-of",
    "source": "{365abb72-55f1-5cd8-0000-00103d1e3300}",
    "destination": "C:\\Windows\\system32\\cmd.exe /C c:\\Windows\\system32\\calc.exe",
    "label": "ParentCommandLine"
  }
]
~~~~

# License

The software is free software released under the GNU Affero General Public License.

Copyright (c) 2020 Alexandre Dulaunoy


