# Python_SNMP_Sweep
Python SNMPv2C scanner

The scanner will scan a given subnet for snmp hosts (SNMPv2c) and transverses the
SNMP tree up to 3 OID level deep.

REQUIREMENTS:

pysnmp
ipaddress

USAGE:
python3 snmp_sweep.py 192.168.1.0/24 -c public -o findings.txt

("-c", "--community", default="public") if none is provided.
