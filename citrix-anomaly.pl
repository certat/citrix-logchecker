#!/usr/bin/perl -w
#
# Parse citrix netscaler logs to check for signs of CVE-2023-4966 exploitation
#
# 2023-10-26  Otmar Lendl <lendl@cert.at>
#
# On a Debian box, this needs apt install libnet-cidr-perl libnet-patricia-perl
# if you want to use -p
#
# The logline prefixes can vary between different systems / log daemons.
# The code tries to ignore this and only uses the timestamp that citrix itself
# sends to syslog.
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

	# load them only of we need to read the prefix file.
	require Net::CIDR;
	require Net::Patricia;

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
my ($day, $lastday, $logins, $stats) = (0,0,0,0,0);
while(<>) {
	chomp;

# the logfile layout (especially the beginning of the line) can vary between systems an log daemons

# looking for a SSLVPN message like:
# Oct  1 06:02:44 netscaler 10/01/2023:06:02:44  C-SYS-F2-003 0-PPE-4 : default SSLVPN LOGIN 104413247 0 : Context user@example.com@a.b.c.d - SessionId: 34921 - User user@example.com - Client_ip a.b.c.d - Nat_ip "Mapped Ip" - Vserver a.b.c.d:443 - Browser_type "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36" - SSLVPN_client_type ICA - Group(s) "N/A"
# or
# 2023-08-01T00:14:15.285005+00:00 172.17.7.7  2023/08/01:00:14:15 GMT mpx2 0-PPE-1 : default SSLVPN LOGIN 18219290 0 : Context random.loser@a.b.c.d - SessionId: 11364 - User random.loser - Client_ip a.b.c.d - Nat_ip "Mapped Ip" - Vserver a.b.c.d:443 - Browser_type "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safa" - SSLVPN_client_type ICA - Group(s) "PORTAL"
# or
# Nov  2 05:31:28 <local0.info> 10.68.166.19  11/02/2023:04:31:28 GMT EXT 0-PPE-0 : default SSLVPN LOGIN 4913897 0 : Context user@ip - SessionId: 21066 - User user- Client_ip 1.2.3.4 - Nat_ip "Mapped Ip" - Vserver 5.6.7.8:443 - Browser_type "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" - SSLVPN_client_type ICA - Group(s) "N/A"
#


# new approach (2023-11-03): ignore the initial syslog artefacts and go straight to the netscaler content. Problem: timestamps vary by locale settings

	if ( m{
		(?<ts>(?<day>\d\d/\d\d/\d\d\d\d|\d\d\d\d/\d\d/\d\d):\d\d:\d\d:\d\d)\s(GMT)?\s	# citrix timestamp, both in MM/DD/YYYY and YYY/MM/DD format if w or w/o GMT timezone 
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
		$day = $p1{day};

		if ($p1{feature} eq 'SSLVPN' and $p1{message} eq 'LOGIN') {
			handle_sslvpn_login(\%p1);
			$logins++;
		} elsif ($p1{feature} eq 'SSLVPN' and $p1{message} eq 'TCPCONNSTAT') {
			handle_sslvpn_tcpconnstat(\%p1);
			$stats++;
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

	if ($day ne $lastday) {
		printf STDERR "\r%s: Logins: %3d, TCPstats: %5d, Roaming Reconnects: %3d               ", $day, $logins, $stats, scalar(keys(%suspect));
	}
	$lastday = $day;
}

print STDERR "\n";

clear_suspect();


sub print_session {
	my $s = $_[0];
	my $nr_timestamps = scalar(@{$sessions{$s}->{timestamps}});

	my $type = (defined($sessions{$s}->{login}->{clienttype})) ? $sessions{$s}->{login}->{clienttype} : 'n/a';

	print "\tSession $s (Type $type): \n";
	printf "\t\t%s: %15s -> %15s (%s -> %s)\n", $sessions{$s}->{tcpstats}->{ts}, $sessions{$s}->{loginip}, $sessions{$s}->{logoutip},
		$sessions{$s}->{loginagg}, $sessions{$s}->{logoutagg};
	printf "\t\t%d TCPSTAT records, %s - %s\n", $nr_timestamps, $sessions{$s}->{timestamps}[0],  $sessions{$s}->{timestamps}[$nr_timestamps-1];
	printf "\t\tVserver %s, Destination %s\n", $sessions{$s}->{tcpstats}->{vserver},  $sessions{$s}->{tcpstats}->{destination};

}

my %state = ();

print "\nSummary:\n========\n\n";
print "** Number of connection-stats without matching logins: ", scalar(keys(%nologin)), "\n";
foreach my $s (keys %nologin) {
	print_session($s);
	$state{nologin}->{$s} = $sessions{$s};
}

print "\n** Number of sessions with reconnects from suspicious sources: ", scalar(keys(%suspect)), "\n";
foreach my $s (keys %suspect) {
	print_session($s);
	$state{suspicious}->{$s} = $sessions{$s};
}

if ($verbose) {
	print "\n** Number of reconnects from cleared sources: ", scalar(keys(%cleared)), "\n";
	foreach my $s (keys %cleared) {
		print_session($s);
		$state{cleared}->{$s} = $sessions{$s};
	}

	print "\n** User logins per aggregate\n";
	foreach my $a (keys %good_sources) {
		print "\t$a\n\t\t", join("\n\t\t", keys(%{$good_sources{$a}})),"\n";
	}

	print "\n\nFull state:\n", Dumper(\%state);

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

		my $id = $full{sessionid} . "-" . $full{context};
	
		if (defined($sessions{$id})) {
			print STDERR "Session $sessions{$id} already exists.\n";
		}

		$sessions{$id}->{login} = \%full;
		$sessions{$id}->{loginip} = $full{clientip};
		$sessions{$id}->{loginagg} = ip_aggregate($full{clientip});
#		print STDERR "L";

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
		Total_bytes_send\s(?<tbsend>\d+)\s+-\s		# number
		Total_bytes_recv\s(?<tbrecv>\d+)\s+-\s		# number
		Total_compressedbytes_send\s(?<tcbsend>\d+)\s+-\s		# number
		Total_compressedbytes_recv\s(?<tcbrecv>\d+)\s+-\s		# number
		Compression_ratio_send\s(?<compsend>[\d.]+)%\s+-\s		# number%
		Compression_ratio_recv\s(?<comprecv>[\d.]+)%\s+-\s		# number%
		Access\s(?<access>\S+)\s+-\s			# Allowed
		Group\(s\)\s"(?<groups>[^"]+)"			# N/A
		$						# 
	}x) {
		my %full = (%$h1, %+);
		delete($full{rest});
		print "got match: ", Dumper(\%full), "\n" if ($debug);

		unless (defined($full{sessionid}) and (defined($full{context}))) {
			print STDERR "TCPSTATS without a sessionid.\n", Dumper(\%full), "\n";
			return;
		}

		my $id = $full{sessionid} . "-" . $full{context};
		my $source = $full{source}; $source =~ s/:\d+$//;	# don't care about port

		unless (defined($sessions{$id}) and defined($sessions{$id}->{login})) {
#			print STDERR "TCPSTATS for $id that didn't login. Client = $source\n" if ($verbose);
			$nologin{$id}->{$full{user}}++;
			$sessions{$id}->{logoutip} = $source;
			$sessions{$id}->{logoutagg} = ip_aggregate($source);
			$sessions{$id}->{tcpstats} = \%full;
			push(@{$sessions{$id}->{timestamps}}, $full{ts});

# fake login data
			$sessions{$id}->{loginip} = $full{clientip};
			$sessions{$id}->{loginagg} = ip_aggregate($full{clientip});
			
			return;
		}

		my $loginip = $sessions{$id}->{loginip};

		if ($source eq $loginip) {			# no change in client IP
#			print STDERR "s";
		} else {
#			print STDERR "R";
			$sessions{$id}->{logoutip} = $source;
			$sessions{$id}->{logoutagg} = ip_aggregate($source);
			$sessions{$id}->{tcpstats} = \%full;
			push(@{$sessions{$id}->{timestamps}}, $full{ts});
			$suspect{$id}++;
		}
	} else {
		print STDERR "cannot parse $h1->{rest}";
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

	print "clear_suspect: Initially ", scalar(@sus_ids), " suspect sessions. ", scalar(keys %cleared), " sessions cleared, ",
			scalar(keys %suspect), " sessions still suspect.\n";

}
