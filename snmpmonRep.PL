#! -*- perl -*-

my $script = <<'EOF';
~startperl~ -w
#
#
#   SNMP::Monitor - a Perl package for monitoring remote hosts via SNMP
#
#
#   Copyright (C) 1998    Jochen Wiedmann
#                         Am Eisteich 9
#                         72555 Metzingen
#                         Germany
#
#                         Phone: +49 7123 14887
#                         Email: joe@ispsoft.de
#
#   All rights reserved.
#

use strict;


require Getopt::Long;
require SNMP::Monitor;
require Time::Local;


############################################################################
#
#   Constant variables
#
############################################################################

my $VERSION = 'snmpmonRep, 29-Oct-1998, Copyright (C) 1998 by Jochen Wiedmann';
my $ETC_DIR = "~etc_dir~";
my $CONFIG_FILE = "$ETC_DIR/configuration";
my $MAIL_COMMAND = "/usr/ucb/mail -s \$subject \$recipient";


############################################################################
#
#   Global variables
#
############################################################################

use vars qw($debugging $verbose);

$debugging = 0;

my $configFile = $CONFIG_FILE;


############################################################################
#
#   Name:    Usage
#
#   Purpose: Print usage message and exit
#
############################################################################

sub Usage () {
    print <<"USAGE";
Usage: $0 [options]

Possible options are:

    --from <dd.mm.yyyy> Start report at the given date, defaults to the
			first day of the previous month.
    --to <dd.mm.yyyy>   Stop report at the given date, defaults to the
			first day of the current month.
    --help		Show this message.
    --version		Print version number and exit.
    --config <file>     Read configuration from <file>, defaults to
                        $CONFIG_FILE.
    --debug             Run in debugging mode; don't do anything, just
			show what would be done.
    --verbose           Run in verbose mode.

$VERSION
USAGE
    exit 1;
}


############################################################################
#
#   Name:    GetTime
#
#   Purpose: Transfrom date string into Unix time.
#
#   Inputs:  Date string
#
#   Returns: Unix time; dies in case of error
#
############################################################################

sub GetTime ($) {
    my $str = shift;
    if ($str !~ /^(\d\d)\.(\d\d)\.(\d\d\d\d)$/) {
	die "Cannot parse date string $str";
    }
    Time::Local::timelocal(0, 0, 0, $1, $2-1, $3-1900);
}


############################################################################
#
#   Name:    ReportInterface
#
#   Purpose: Generate interface report
#
#   Inputs:  $dbh       - Database handle
#            $host      - Config file host
#            $interface - Config file interface
#            $from, $to - Report times
#
#   Returns: Report data
#
############################################################################

sub _FromUnixTime {
    my($sec, $min, $hour, $mday, $mon, $year) = localtime(shift);
    sprintf('%04d-%02d-%02d %02d:%02d:%02d',
	    $year+1900, $mon+1, $mday, $hour, $min, $sec);
}

sub ReportInterface ($$$$$) {
    my($dbh, $host, $interface, $from, $to) = @_;

    my $query = sprintf("SELECT SUM(INOCTETS), SUM(OUTOCTETS),"
			. " AVG(OPERSTATUS=1) FROM SNMPMON_IFLOAD WHERE"
			. " INTERVAL_END >= %s AND INTERVAL_END < %s "
			. " AND INTERFACE = %s AND HOST = %s",
			$dbh->quote(_FromUnixTime($from)),
			$dbh->quote(_FromUnixTime($to)),
			$interface->{'num'},
			$dbh->quote($host->{'name'}));
    if ($verbose) {
	print "Interface query: $q\n";
    }
    my $sth = $dbh->prepare($q);
    $sth->execute();
    my $ref = $sth->fetchrow_arrayref();

    my $ifInOctets = $ref ? $ref->[0] : 0;
    my $ifOutOctets = $ref ? $ref->[1] : 0;
    my $sumOctets = $ifInOctets + $ifOutOctets;
    my $avg = $ref ? $ref->[2] : 0;
    { 'in' => $ifInOctets,
      'out' => $ifOutOctets,
      'sum' => $sumOctets,
      'avg' => $avg,
      'host' => $host->{'name'},
      'description' => $interface->{'short_message'} ||
	               $interface->{'description'},
      'interface' => $interface->{'num'}
    }
}


############################################################################
#
#   Name:    Report
#
#   Purpose: Generate report
#
#   Inputs:  $configFile - Config file location
#            $from, $to - Report times
#
#   Returns: Nothing, dies in case of trouble.
#
############################################################################

sub Report ($$$) {
    my($configFile, $from, $to) = @_;
    my $config = SNMP::Monitor->Configuration($configFile);
    my $reports = {};

    my $dbh = DBI->connect($config->{'dbi_dsn'}, $config->{'dbi_user'},
			   $config->{'dbi_pass'}, { 'RaiseError' => 1 });

    foreach my $host (values %{$config->{'hosts'}}) {
	foreach my $interface (@{$host->{'interfaces'}}) {
	    if (my $addr = $interface->{'report'}) {
		if ($verbose) {
		    print("Reporting host ", $host->{'name'},
			  "interface ", $interface->{'num'}, "\n");
		}
		my $r = ReportInterface($dbh, $host, $interface, $from, $to);
		foreach my $a (split(/,/, $addr)) {
		    $a =~ s/^\s+//;
		    $a =~ s/\s+$//;
		    if (!$reports->{$a}) {
			$reports->{$a} = [];
		    }
		    push(@{$reports->{$a}}, $r);
		}
	    } else {
		if ($verbose) {
		    print("Ignoring host ", $host->{'name'},
			  "interface ", $interface->{'num'}, "\n");
		}
	    }
	}
    }

    my($sec, $min, $hour, $to_d, $to_m, $to_y, $from_d, $from_m, $from_y);
    ($sec, $min, $hour, $from_d, $from_m, $from_y) = localtime($from);
    ($sec, $min, $hour, $to_d, $to_m, $to_y) = localtime($to);

    $from_y += 1900;
    $from_m += 1;
    $to_y += 1900;
    $to_m += 1;

    while (my ($a, $list) = each %$reports) {
	my $msg = qq{

Interfaceauslastung vom $from_d.$from_m.$from_y - $to_d.$to_m.$to_y:

};
	$msg .= sprintf("\n%20s %-12s %12s %13s %5s\n",
			"Interface", "Bytes In", "Bytes Out", "Summe",
			"Uptime");
	$msg .= "\n";
	foreach my $l (@$list) {
	    $msg .= sprintf("%20s %12s %12s %13s %5.2f\n",
			    $l->{'description'},
			    $l->{'in'}, $l->{'out'}, $l->{'sum'},
			    $l->{'avg'}*100);
	}

	if ($verbose) {
	    print "Sending message to $a:\n\n$msg\n\n";
	}
	if (!$debugging) {
	    my $command = $MAIL_COMMAND;
	    $command =~ s/\$subject/Interfaceauslastung/;
	    $command =~ s/\$recipient/$a/;
	    if (!open(PIPE, "| $command")  ||  !(print PIPE $msg)  ||
		!close(PIPE)) {
		print STDERR "Error while sending mail via $command: $!";
	    }
	}
    }

    $dbh->disconnect();
}


############################################################################
#
#   This is main().
#
############################################################################

{
    my $o = {};
    &Getopt::Long::GetOptions($o, '--from=s', '--to=s', '--debug',
			      '--help', '--config=s', '--verbose',
			      '--version');
    if ($o->{'help'}) {
	&Usage();
    }
    if ($o->{'version'}) {
	print "$VERSION\n";
	exit 0;
    }
    if ($o->{'debug'}) {
	$debugging = 1;
	$verbose = 1;
    }
    if ($o->{'verbose'}) {
	$verbose = 1;
    }
    if ($o->{'config'}) {
	$configFile = $o->{'config'};
    }

    my $from;
    if ($o->{'from'}) {
	$from = GetTime($o->{'from'});
    } else {
	my($sec, $min, $hour, $mday, $mon, $year) = localtime(time);
	if (--$mon < 0) {
	    $mon = 11;
	    --$year;
	}
	$from = Time::Local::timelocal(0, 0, 0, 1, $mon, $year);
    }

    my $to;
    if ($o->{'to'}) {
	$to = GetTime($o->{'to'});
    } else {
	my($sec, $min, $hour, $mday, $mon, $year) = localtime(time);
	$to = Time::Local::timelocal(0, 0, 0, 1, $mon, $year);
    }

    Report($configFile, $from, $to);
}

EOF

require SNMP::Monitor;
my $config = SNMP::Monitor->Configuration('configuration');

require Config;
$config->{'startperl'} = $Config::Config{'startperl'};
$config->{'startperl'} = $Config::Config{'startperl'}; # Make -w happy ...


$script =~ s/\~(\w+)\~/$config->{$1}/eg;

if (!open(FILE, ">snmpmonRep")  ||  !print FILE ($script)  ||  !close(FILE)) {
    die "Error while writing snmpmonRep script: $!";
}
