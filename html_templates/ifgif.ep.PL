#! -*- perl -*-

my $script = <<'EOF';
<ep-package name="SNMP::Monitor::EP" require=1>
<ep-snmpmon-auth configuration="~etc_dir~/configuration" user=""
	epparse-interface="$cgi->if$">
<ep-database epparse-dsn="$snmpmon_config->dbi_dsn$"
             epparse-user="$snmpmon_config->dbi_user$"
             epparse-password="$snmpmon_config->dbi_pass$">
<ep-perl package=temp>
    my $self = $_;
    my $cgi = $self->{cgi};
    $self->snmpmon_auth({'configuration' => "/etc/snmpmon/configuration",
			 'interface' => $cgi->param('if')});
    my $if = $self->{snmpmon_interfaces}->[0];
    my($to_y) = $cgi->param('to_y');
    my $to;
    my($sec,$min,$hour,$mday,$mon,$year);
    require Time::Local;
    if ($to_y) {
	my($to_m) = $cgi->param('to_m');
	my($to_d) = $cgi->param('to_d');
	if ($to_y < 98) {
	    $to_y += 2000;
	} elsif ($to_y < 100) {
	    $to_y += 1900;
	}
        $to = Time::Local::timelocal(0, 0, 12, $to_d, $to_m-1,
                                       $to_y-1900);
    } else {
        ($sec,$min,$hour,$mday,$mon,$year) = localtime(time);
        $to = Time::Local::timelocal(0, 0, 12, $mday, $mon, $year); 
    }
    $to += 1 * 24 * 3600;
    ($sec,$min,$hour,$mday,$mon,$year) = localtime($to);
    my $to_range = sprintf("%04d-%02d-%02d,%02d:%02d:%02d",
			$year+1900, $mon+1, $mday, 0, 0, 0);
    $to = Time::Local::timelocal(0, 0, 0, $mday, $mon, $year);

    my $from = $to - ($cgi->param('days') || 1) * 24 * 3600;
    ($sec,$min,$hour,$mday,$mon,$year) = localtime($from);
    my $from_range = sprintf("%04d-%02d-%02d,%02d:%02d:%02d",
			     $year+1900, $mon+1, $mday, 0, 0, 0);
    $from = Time::Local::timelocal(0, 0, 0, $mday, $mon, $year);

    my $query = "SELECT UTILIZATION, INTERVAL_END FROM SNMPMON_IFLOAD"
        . " WHERE INTERVAL_END > FROM_UNIXTIME($from) AND"
        . " INTERVAL_END < FROM_UNIXTIME($to) AND HOST = "
        . $self->{dbh}->quote($if->{host}->{name})
        . " AND INTERFACE = " . $if->{interface}->{num}
        . " ORDER BY INTERVAL_END";
    my $sth = $self->{dbh}->prepare($query);
    $sth->execute();
    if (!$sth->rows()) {
        die "No rows";
    }
    my $command = $self->{snmpmon_config}->{path_gnuplot} . " | " .
        $self->{snmpmon_config}->{path_ppmtogif} . " 2>/dev/null";
    my $fh;
    if ($self->{debug}) {
        $self->print("Creating pipe to the following command:\n$command\n");
    } else {
        $fh = Symbol::gensym();
        if (!open($fh, "| $command")) {
            die "Cannot open pipe to command $command: $!";
        }
	$| = 1;
        $self->print("content-type: image/gif\n\n");
    }
    my $critical = $self->{cgi}->param('critical') ?
        (", f(x) = " . $self->{cgi}->param('critical') . ", f(x)") : '';
    my $scale = $self->{cgi}->param('scale') || 100;
    my $title = $self->{cgi}->param('title')
        || $if->{interface}->{short_message}
        || $if->{interface}->{description};

    my $output = <<"GNUPLOT";
set size noratio 1.5,0.4
set title '$title'
set terminal pbm color
set timefmt '%Y-%m-%d,%H:%M:%S'
set xdata time
set xrange [ "$from_range" : "$to_range" ]
set yrange [ 0 : $scale ]
set ylabel 'Auslastung [%]
set format x \"%H:%M\\n%d.%m\"
plot '-' using 1:2 with lines $critical
GNUPLOT
    if ($self->{debug}) {
        $self->print($output);
    } else {
        print $fh $output;
    }

    my($ref, $time, $utilization);
    while ($ref = $sth->fetchrow_arrayref) {
        ($utilization, $time) = @$ref;
        $time =~ s/ /,/;
        if ($self->{debug}) {
            $self->print("$time $utilization\n");
        } else {
            print $fh "$time $utilization\n";
        }
    }
    if (!$self->{debug}) {
        close($fh);
    }
    $self->Stop();
</ep-perl>
EOF

require SNMP::Monitor;
my $config = SNMP::Monitor->Configuration('configuration');

require Config;
$config->{'startperl'} = $Config::Config{'startperl'};
$config->{'startperl'} = $Config::Config{'startperl'}; # Make -w happy ...


$script =~ s/\~(\w+)\~/$config->{$1}/eg;

if (!(-d "html")  &&  !(mkdir "html", 0755)) {
    die "Cannot create directory 'html': $!";
}
if (!open(FILE, ">html/ifgif.ep")  ||
    !(print FILE ($script))  ||  !close(FILE)) {
    die "Error while writing html/index.ep file: $!";
}
