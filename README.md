# evtx-toolkit (WiP)

Tool to read EVTX files including SYSMON and convert to JSON, MISP Objects and Graph stream

# Usage

~~~~
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

# License


