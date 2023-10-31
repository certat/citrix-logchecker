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

# Requirements

The script needs Net::CIDR and Net::Patricia (you want to use the -p feature) which might not be installed on all Linux servers. On Debian-based systems, use

        sudo apt install libnet-cidr-perl libnet-patricia-perl

to install them.

A file with the global routing table as of 2023-10-27 is included in this repo. It needs to be decompressed.

The logline prefixes can vary between different systems / log daemons.
You might need to adapt the code at line ~110, by commenting / uncommenting adapting the patterns for timestamps.

# Background and Algorithm

CVE-2023-4966 leaks session cookies which allows attackers to reconnect to existing Citrix sessions.

This script looks for "SSLVPN LOGIN" and "SSLVPN TCPCONNSTAT" syslog lines (pre-filtering with grep for these lines makes sense) 
and checks which sessions either don't have a matching LOGIN line or change client IP address over its lifetime.

The script uses successful initial logins as sign that a source network is benign. If there are only reconnects from 
a source network, but no initial connects from there, then these reconnects are suspicious. This is not done on a 
pure IP-address basis, there are three aggrgation schemes implemented:

* trival /24
* aggregate to prefix according to the routing table
* aggregate to AS according to the routing table

The latter two algorithms need a file that matches prefixes to ASN. An example is supplied in this repo.

