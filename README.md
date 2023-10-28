# citrix-logchecker
Parse citrix netscaler logs to check for signs of CVE-2023-4966 exploitation

Written by Otmar Lendl.

# Usage:

        ./citrix-anomaly.pl [-d] [-v] [-h] [-p file] [-a X] [logfiles]

        This script parse citrix netscale syslog files and looks for session
        reconnects that might be the result of a CVE-2023-4966 exploitation.

        Parameters:

                -d  Debug
                -v  Verbose
                -h  This help
                -a  Set aggregation type. Possible values
                        b (default) simple /24 aggregation
                        a aggregate by ASN
                        p aggregate to routing table prefix
                -p path to a routing table dump. Syntax: "prefix asn" per line
