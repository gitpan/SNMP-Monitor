#! -*- perl -*-

my $script = <<'EOF';
<ep-package name="SNMP::Monitor::EP" require=1>
<ep-snmpmon-auth configuration="~etc_dir~/configuration" user="">
<ep-perl package=temp>
    my $self = $_;
    my(undef, undef, undef, $date_d, $date_m, $date_y) = localtime(time());
    $self->{'date_d'} = $date_d;
    $self->{'date_m'} = $date_m+1;
    $self->{'date_y'} = $date_y+1900;

    my $cgi = $self->{'cgi'};
    $self->{'to_d'} = $cgi->param('to_d');
    $self->{'to_m'} = $cgi->param('to_m');
    $self->{'to_y'} = $cgi->param('to_y');
    $self->{'from_d'} = $cgi->param('from_d');
    $self->{'from_m'} = $cgi->param('from_m');
    $self->{'from_y'} = $cgi->param('from_y');

    my($ifc,$dif,@if_list,$if_id);
    my $cgi = $self->{cgi};
    $self->{snmpmon_if_displayed} = [];
    foreach $ifc ($cgi->param()) {
 	if ($ifc =~ /^if_\d+$/) {
 	    $if_id = $cgi->param($ifc);
 	    if ($if_id) {
 		push(@if_list, $if_id);
 		foreach $dif (@{$self->{snmpmon_interfaces}}) {
 		    if ($dif->{host}->{name} . ":" . $dif->{interface}->{num}
 			eq $if_id) {
 			$dif->{selected} = "CHECKED";
			push(@{$self->{snmpmon_if_displayed}}, $dif);
 			last;
 		    }
 		}
 	    }
 	}
    }
    $self->{snmpmon_display} = @{$self->{snmpmon_if_displayed}};

    ''
</ep-perl>
<HTML><HEAD>

<STYLE TYPE="text/css">
td {font-size: 11px; font-family: Verdana;}
th {font-size: 11px; font-family: Verdana;}
H1 {font-size: 20px; font-family: Verdana;}
H2 {font-size: 14px; font-family: Verdana;}
H3 {font-size: 14px; font-family: Verdana;}
A:LINK { font-family: Verdana;  color: #0097BF; }
</STYLE>

<TITLE>SNMP-Monitor - Interface statistics</TITLE></HEAD>
<BODY BGCOLOR="#FFFFFF">
<H1><STRONG>SNMP-Monitor - Interface statistics</STRONG></H1>
<CENTER>
<FORM ACTION=stats.ep METHOD=POST>
<TABLE WIDTH=500>
  <TR BGCOLOR="#CCCCCC"><TH>Interface</TH><TH>Yes/No</TH></TR>
 <ep-list items="snmpmon_interfaces" item="if">
  <TR><TD>$if->interface->short_message$</TD>
      <TD VALIGN=CENTER>
        <INPUT TYPE=checkbox NAME="if_$i$" $if->selected$
         VALUE="$if->host->name$:$if->interface->num$"></TD>
  </TR>
 </ep-list>
</TABLE>
<TABLE>
  <TR><TH>From:</TD>
      <TD><ep-select name=from_d range="1..31" item=d
           epparse-selected="$from_d$"
          ><OPTION $selected$>$d$</ep-select></TD>
      <TD>.</TD>
      <TD><ep-select name=from_m range="1..12" item=m
           epparse-selected="$from_m$"
          ><OPTION $selected$>$m$</ep-select></TD>
      <TD>.</TD>
      <TD><ep-select name=from_y item=y
           epperl-range="($_->{'date_y'}-4).'..'.$_->{'date_y'}"
           epparse-selected="$from_y$"
          ><OPTION $selected$>$y$</ep-select></TD>
  <TR><TH>To:</TD>
      <TD><ep-select name=to_d range="1..31" item=d
           epparse-selected="$to_d$"
          ><OPTION $selected$>$d$</ep-select></TD>
      <TD>.</TD>
      <TD><ep-select name=to_m range="1..12" item=m
           epparse-selected="$to_m$"
          ><OPTION $selected$>$m$</ep-select></TD>
      <TD>.</TD>
      <TD><ep-select name=to_y item=y
           epperl-range="($_->{'date_y'}-4).'..'.$_->{'date_y'}"
           epparse-selected="$to_y$"
          ><OPTION $selected$>$y$</ep-select></TD>
</TABLE>
<INPUT TYPE=SUBMIT VALUE="Show Me">
</FORM>
</CENTER>
<ep-if epparse-eval=$snmpmon_display$>
<ep-database epparse-dsn="$snmpmon_config->dbi_dsn$"
             epparse-user="$snmpmon_config->dbi_user$"
             epparse-password="$snmpmon_config->dbi_pass$">
<ep-perl package=temp>
    my $self = $_;
    my $dbh = $self->{'dbh'};
    my $if;
    require Time::Local;
    my $from = Time::Local::timelocal(0, 0, 0, $self->{'from_d'},
	                              $self->{'from_m'}-1,
                                      $self->{'from_y'}-1900);
    my $to = Time::Local::timelocal(0, 0, 0, $self->{'to_d'},
	  	                    $self->{'to_m'}-1,
                                    $self->{'to_y'}-1900);
    my $secs = $self->{'secs'} = ($to - $from) > 0 ? ($to - $from) : 0;
    while ($self->{'secs'} =~ s/(\d{1,3})(\d{3})(\s.*)?$/$1 $2$3/) { }

    my $query = "SELECT SUM(INOCTETS), SUM(OUTOCTETS), AVG(OPERSTATUS=1)"
        . " FROM SNMPMON_IFLOAD WHERE INTERVAL_END >= FROM_UNIXTIME($from) AND"
        . " INTERVAL_END < FROM_UNIXTIME($to) AND INTERFACE = %s"
        . " AND HOST = %s";

    my $if;
    foreach $if (@{$self->{snmpmon_if_displayed}}) {
       my $q = sprintf($query, $if->{'interface'}->{'num'},
                       $dbh->quote($if->{'host'}->{'name'}));
       $self->print("Executing query: $q\n");
       my $sth = $dbh->prepare($q);
       $sth->execute();
       my $ref = $sth->fetchrow_arrayref();

       my $inOctets = $ref ? $ref->[0] : 0;
       my $outOctets = $ref ? $ref->[1] : 0;
       my $avgOctets = $secs ?
           sprintf("%.0f", ((8*($inOctets+$outOctets))/$secs)) : 0;

       while ($inOctets =~ s/(\d{1,3})(\d{3})(\s.*)?$/$1 $2$3/) { }
       $if->{'in_octets'} = $inOctets;

       while ($outOctets =~ s/(\d{1,3})(\d{3})(\s.*)?$/$1 $2$3/) { }
       $if->{'out_octets'} = $outOctets;

       while ($avgOctets =~ s/(\d{1,3})(\d{3})(\s.*)?$/$1 $2$3/) { }
       $if->{'avg_octets'} = $avgOctets;

       $if->{'up_percent'} = $ref ? sprintf("%.2f", ($ref->[2]*100)) : '';
    }
    ''
</ep-perl>
<H3>Interface stats</H3>
<CENTER>
<P>
<TABLE WIDTH=300>
  <TR BGCOLOR="#CCCCCC">
    <TH>From:</TH>
    <TH>To:</TH>
    <TH>Secs:</TH>
  </TR>
  <TR>
    <TD>$from_d$-$from_m$-$from_y$</TD>
    <TD>$to_d$-$to_m$-$to_y$</TD>
    <TD ALIGN=RIGHT>$secs$</TD>
  </TR>
</TABLE>
</P>
<TABLE WIDTH=500>
  <TR BGCOLOR="#CCCCCC">
    <TH>Interface</TH><TH>Incoming Octets</TH><TH>Outgoing Octets</TH>
    <TH>Average (Bit/sec)</TH><TH>Uptime (Percent)</TH></TR>
 <ep-list items="snmpmon_if_displayed" item="if">
  <TR><TD>$if->interface->short_message$</TD>
      <TD ALIGN=RIGHT>$if->in_octets$</TD>
      <TD ALIGN=RIGHT>$if->out_octets$</TD>
      <TD ALIGN=RIGHT>$if->avg_octets$</TD>
      <TD ALIGN=RIGHT>$if->up_percent$</TD></TR>
 </ep-list>
</TABLE>
</CENTER>
</ep-if>
</BODY>
</HTML>
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
if (!open(FILE, ">html/stats.ep")  ||
    !(print FILE ($script))  ||  !close(FILE)) {
    die "Error while writing html/stats.ep file: $!";
}
