#! -*- perl -*-

my $script = <<'EOF';
<ep-package name="SNMP::Monitor::EP" require=1>
<ep-snmpmon-auth configuration="~etc_dir~/configuration" user="">
<ep-perl package=temp>
    my $self = $_;
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

    my(undef, undef, undef, $date_d, $date_m, $date_y) = localtime(time());
    $self->{'date_d'} = $date_d;
    $self->{'date_m'} = $date_m+1;
    $self->{'date_y'} = $date_y+1900;

    '';
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

<TITLE>SNMP-Monitor - Interface utilization</TITLE></HEAD>
<BODY bgcolor="#FFFFFF">
<H1><STRONG>SNMP-Monitor - Interface utilization</STRONG></H1>
<H3>Select interfaces being displayed:</H3>
<CENTER>
<FORM ACTION=graph.ep METHOD=POST>
  <TABLE WIDTH=500>
    <TR BGCOLOR="#CCCCCC"><TH>Interface</TH><TH>Yes/No</TH></TR>
   <ep-list items="snmpmon_interfaces" item="if">
    <TR><TD>$if->interface->short_message$</TD>
        <TD ALIGN=CENTER>
          <INPUT TYPE=checkbox NAME="if_$i$" $if->selected$
           VALUE="$if->host->name$:$if->interface->num$"></TD>
    </TR>
   </ep-list>
  </TABLE>
  <TABLE>
    <TR><TH>Show the last</TH>
        <TD><ep-select range="1..5" item=d name=days
             epparse-selected="$cgi->days$"
            ><OPTION $selected$>$d$</ep-select></TD>
        <TH>days until</TH>
        <TD><ep-select range="1..31" item=d name=to_d
             epparse-selected="$cgi->to_d$"
            ><OPTION $selected$>$d$</ep-select
            >.<ep-select range="1..12" item=m name=to_m
               epparse-selected="$cgi->to_m$"
            ><OPTION $selected$>$m$</ep-select
            >.<ep-select epperl-range="($_->{date_y}-4).'..'.$_->{date_y}"
               item=y name=to_y epparse-selected="$cgi->to_y$"
            ><OPTION $selected$>$y$</ep-select></TD>
    </TR>
    <TR><TH>Scale:</TH>
        <TD><ep-select range="100,90,80,70,60,50,40,30,20,10,5"
             name="scale" item=s epparse-selected="$cgi->scale$"
            ><OPTION VALUE="$s$" $selected$>$s$ %</ep-select></TD>
    </TR>
  </TABLE>         
  <INPUT TYPE=SUBMIT VALUE="Show Me">
</FORM>
</CENTER>
<ep-if epparse-eval="$snmpmon-display$">
<H2>Display</H2>
<ep-list items="snmpmon_if_displayed" item="if">
<H3>$if->interface->short_message$</H3>
<CENTER><IMG SRC="ifgif.ep?if=$if->host->name$:$if->interface->num$&scale=$cgi->scale$&to_y=$to_y$&to_m=$to_m$&to_d=$to_d$&days=$cgi->days$">
</CENTER>
</ep-list>
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
if (!open(FILE, ">html/graph.ep")  ||
    !(print FILE ($script))  ||  !close(FILE)) {
    die "Error while writing html/index.ep file: $!";
}
