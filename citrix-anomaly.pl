#!/usr/bin/perl -w
#
# Parse citrix netscaler logs to check for signs of CVE-2023-4966 exploitation
#
# 2023-10-26  Otmar Lendl <lendl@cert.at>
#
# On a Debian box, this needs apt install libnet-cidr-perl libnet-patricia-perl
#

use strict;
use Data::Dumper;
use Getopt::Long;

my $debug = 0;
my $verbose = 0;
my $help = 0;
my $prefix_file;
my $agg_algo = "b";
my $cidrtree;


&GetOptions (
	"d" => \$debug,
        "v" => \$verbose,
        "h" => \$help,
        "p=s" => \$prefix_file,
        "a=s" => \$agg_algo,
);

if ($help) {
	print <<EOM;
Usage:

	$0 [-d] [-v] [-h] [-p file] [-a X] [logfiles]

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

EOM

exit;
}
die 'Aggregation algorithm (-a) needs to be either "b", "a", or "p".' unless ($agg_algo =~ /^[abp]$/);
die 'Aggregation algorithms "a" and "p" require a prefix file (-p)' if (($agg_algo =~ /^[ap]$/) and !defined($prefix_file));

if (defined($prefix_file)) {
	die "Give a valid filename for -p\n" unless ($prefix_file =~ /^[\w_.\/-]+$/ and -f $prefix_file);

	use Net::CIDR ':all';
	use Net::Patricia;

	$cidrtree = new Net::Patricia;

	print STDERR "Loading Routing table : " if ($debug);
	my $count = 0;
	
	open(RT, $prefix_file) or die "cannot open $prefix_file";
	while($_ = <RT>) {
		if (/^(v4table )?([0-9.\/]+)\s(\d+)/) {
			$cidrtree->add_string($2, ($agg_algo eq "a") ? $3 : $2);	# map to ASN or prefix itself
			if ($debug) {
				print STDERR "." unless ($count++ % 1000)
			}
		}
	}
	close(RT);
	print STDERR "\nLoaded $count prefixes\n" if ($debug);

	$cidrtree->add_string("0.0.0.0/0", "ASDEFAULT");	# make sure we get always a match
}

$| = 1;

# Logfile definition see https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference/current-release.html

my %sessions;
my %suspect;
my %cleared;
my %nologin;
my %good_sources;

my %p1;
while(<>) {
	chomp;

# looking for a SSLVPN LOGIN message like:
# Oct  1 06:02:44 netscaler 10/01/2023:06:02:44  C-SYS-F2-003 0-PPE-4 : default SSLVPN LOGIN 104413247 0 : Context user@example.com@a.b.c.d - SessionId: 34921 - User user@example.com - Client_ip a.b.c.d - Nat_ip "Mapped Ip" - Vserver a.b.c.d:443 - Browser_type "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36" - SSLVPN_client_type ICA - Group(s) "N/A"
	if ( m{^
		(?<ts1>\w\w\w\s\s?\d?\d\s\d\d:\d\d:\d\d)\s	# first timestamp
		(?<hostname>[\w-]+)\s				# 
		(?<ts2>\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d)\s+	# second timestamp
		(?<code1>[\w-]+)\s				# e.g. C-SYS-F2-003
		(?<code2>[\w-]+)\s				# e.g. 0-PPE-4
		:\s
		(?<severity>[\w-]+)\s				# e.g. default
		(?<feature>[\w-]+)\s				# e.g. SSLVPN
		(?<message>[\w-]+)\s				# e.g. LOGIN
		(?<logid>[\d]+)\s				# 
		(?<pad1>[\d]+)\s				# e.g. 0
		[:]\s
		(?<rest>.*)$					# parse the rest later depending on type of log message
	
	}x) {
		%p1 = %+;

		if ($p1{feature} eq 'SSLVPN' and $p1{message} eq 'LOGIN') {
			handle_sslvpn_login(\%p1);
		} elsif ($p1{feature} eq 'SSLVPN' and $p1{message} eq 'TCPCONNSTAT') {
			handle_sslvpn_tcpconnstat(\%p1);
		} else {
			print "Not processing $p1{feature} /  $p1{message}\n" if ($verbose);
		}
#		print "got match: ", Dumper(\%+), "\n";
	} elsif ( m{^
		(?<ts1>\w\w\w\s\s?\d?\d\s\d\d:\d\d:\d\d)\s	# first timestamp
		(?<hostname>[\w-]+)\s				# 
		["]$						# logline containing only a "
	}x) {
		next;						# we can ignore those.
	} else {
		print STDERR "No match for: $_\n" if ($verbose);
		next;
	}

}

print STDERR "\n";

clear_suspect();

if ($verbose) {
	print "\n\n";
	print "Aggregated Login statistics: ", Dumper(\%good_sources);
	print "\n\n";
	print "Cleared reconnect SessionIDs: ", Dumper(\%cleared);
	print "\n\n";
	foreach my $s (keys %cleared) {
		print "Cleared Session $s: \n", Dumper($sessions{$s}), "\n";
	}
}

print "Connection-Stats without Login from: ", Dumper(\%nologin);
print "\n\n";
print "Suspect SessionIDs: ", Dumper(\%suspect);
print "\n\n";

foreach my $s (keys %suspect) {
	print "Suspect Session $s: \n", Dumper($sessions{$s}), "\n";
}

#
# handle logins
#
# 'Context user@example.com@a.b.c.d - SessionId: 25530 - User user@example.com - Client_ip a.b.c.d - Nat_ip "Mapped Ip" - Vserver a.b.c.d:443 - Browser_type "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36 Edg/109.0.1518.1" - SSLVPN_client_type ICA - Group(s) "N/A"',
# does not match 1:1 from the docs:
# SSLVPN 	LOGIN 	INFO 	SSLVPN login succeeds 	
# “User%s-Client_ip%s-““Nat_ip%s-Vserver%s:%d-Browser_type\“%s\“-SSLVPN_client_type%s-Group(s)\“%s\”” 	  	  	  	 

sub handle_sslvpn_login {
	my $h1 = $_[0];

	print "handle_sslvpn_login: got ", Dumper($h1), "\n" if ($debug);
	if ( $h1->{rest} =~ m{^
		Context\s(?<context>\S+)\s-\s			# user@domain@ip
		SessionId:\s(?<sessionid>\d+)\s-\s		# 
		User\s(?<user>\S+)\s-\s				# user@domain
		Client_ip\s(?<clientip>[\d.]+)\s-\s		# a.b.c.d
		Nat_ip\s"(?<natip>[^-]+)"\s-\s			# ?
		Vserver\s(?<vserver>[\d:.]+)\s-\s		# a.b.c.d:p
		Browser_type\s"(?<browsertype>[^"]+)"\s-\s	# Mozilla ...
		SSLVPN_client_type\s(?<clienttype>\S+)\s-\s	# ICA, ...
		Group\(s\)\s"(?<groups>[^"]+)"			# N/A
		$						# 
	}x) {
		my %full = (%$h1, %+);
		delete($full{rest});
		print "got match: ", Dumper(\%full), "\n" if ($debug);
	
		if (defined($sessions{$full{sessionid}})) {
			print STDERR "Session $sessions{$full{sessionid}} already exists.\n";
		}

		$sessions{$full{sessionid}}->{login} = \%full;
		$sessions{$full{sessionid}}->{loginip} = $full{clientip};
		print STDERR "L";

		my $aggr = ip_aggregate($full{clientip});
		$good_sources{$aggr}->{$full{user}}++;
	}

}

#
# handle TCPCONNSTAT
#
# 'Context user@example.com@a.b.c.d - SessionId: 25530 - User user@example.com - Client_ip a.b.c.d - Nat_ip a.b.c.d - Vserver a.b.c.d:443 - Source a.b.c.d:53772 - Destination a.b.c.d:443 - Start_time "10/01/2023:22:45:13 " - End_time "10/01/2023:22:45:16 " - Duration 00:00:03  - Total_bytes_send 0 - Total_bytes_recv 2063 - Total_compressedbytes_send 0 - Total_compressedbytes_recv 0 - Compression_ratio_send 0.00% - Compression_ratio_recv 0.00% - Access Allowed - Group(s) "N/A"'
# 
# does not match 1:1 from the docs:
# SSLVPN 	TCPCONNSTAT 	INFO 	Logs the TCP connection related information for a connection belonging to a SSLVPN session 	
# “User%s-Client_ip%s-Nat_ip%s-Vserver%s:%d-““Source%s:%d-Destination%s:%d-Start_time\“%s\“-End_time\“%s\”-““Duration%s-Total_bytes_send%d-Total_bytes_recv%d-““Total_compressedbytes_send%d-Total_compressedbytes_recv%d-““Compression_ratio_send%d.%02u%%-Compression_ratio_recv%d.%02u%%-Access%s-Group(s)\“%s\”” 	  	  	  	 


sub handle_sslvpn_tcpconnstat {
	my $h1 = $_[0];

	print "handle_sslvpn_tcpconnstat: got ", Dumper($h1), "\n" if ($debug);
	if ( $h1->{rest} =~ m{^
		Context\s(?<context>\S+)\s-\s			# user@domain@ip
		SessionId:\s(?<sessionid>\d+)\s-\s		# 
		User\s(?<user>\S+)\s-\s				# user@domain
		Client_ip\s(?<clientip>[\d.]+)\s-\s		# a.b.c.d
		Nat_ip\s"?(?<natip>[^-]+?)"?\s-\s			# ?
		Vserver\s(?<vserver>[\d:.]+)\s-\s		# a.b.c.d:p
		Source\s(?<source>[\d:.]+)\s-\s			# a.b.c.d:p
		Destination\s(?<destination>[\d:.]+)\s-\s	# a.b.c.d:p
		Start_time\s"(?<starttime>[^"]+)"\s-\s		# 10/01/2023:22:45:13 
		End_time\s"(?<endtime>[^"]+)"\s-\s		# 10/01/2023:22:45:13 
		Duration\s(?<duration>\S+)\s+-\s		# xx:yy.zz
		Total_bytes_send.*?Compression_ratio_recv\s\S+\s-\s 	# not interested
		Access\s(?<access>\S+)\s+-\s			# Allowed
		Group\(s\)\s"(?<groups>[^"]+)"			# N/A
		$						# 
	}x) {
		my %full = (%$h1, %+);
		delete($full{rest});
		print "got match: ", Dumper(\%full), "\n" if ($debug);

		my $sessionid = $full{sessionid};
		my $source = $full{source}; $source =~ s/:\d+$//;	# don't care about port

		unless (defined($sessionid) and ($sessionid =~ /^\d+$/)) {
			print STDERR "TCPSTATS without a sessionid.\n", Dumper(\%full), "\n";
			return;
		}
		unless (defined($sessions{$sessionid})) {
			print STDERR "TCPSTATS for $sessionid that doesn't exist. Client = $source\n" if ($verbose);
			$nologin{$source}->{$full{user}}++;
			return;
		}

		my $loginip = $sessions{$sessionid}->{loginip};

		if ($source eq $loginip) {			# no change in client IP
			print STDERR "s";
		} else {
			print STDERR "R";
			$sessions{$sessionid}->{logoutip} = $source;
			$sessions{$sessionid}->{tcpstats} = \%full;
			$suspect{$sessionid}++;
		}
	}
}

#
# for the detection of "normal" logins, we need to aggregate ip-addresses
#
sub ip_aggregate {
	my $ip = $_[0];

	if ($agg_algo eq 'b') {		# trivial /24
		my $net = $ip; $net =~ s/\.\d+$//;
		return($net);
	} else {			# a or p
        	return($cidrtree->match_string($ip));
	}
}

# look for session resumptions from harmless addresses
sub clear_suspect {

	my @sus_ids = keys(%suspect);

	foreach my $sus (@sus_ids) {
#		print "looking at session: ", Dumper($sus, $sessions{$sus}), "\n";
		my $agg = ip_aggregate($sessions{$sus}->{logoutip});
		if (exists($good_sources{$agg})) {	# have we seen logins from that origin?
			$cleared{$sus} = $suspect{$sus};
			delete($suspect{$sus});
		}
	}

	print "clear_suspect: Looked at ", scalar(@sus_ids), ". Now ", scalar(keys %cleared), " sessions cleared, ",
			scalar(keys %suspect), " sessions still suspect.\n";

}
