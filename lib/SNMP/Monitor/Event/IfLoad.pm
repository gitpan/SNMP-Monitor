# -*- perl -*-
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
#   You may distribute this module under the terms of either
#   the GNU General Public License or the Artistic License, as
#   specified in the Perl README file.
#

use strict;


require Sys::Syslog;
require DBI;


package SNMP::Monitor::Event::IfLoad;

use vars qw(@ISA $VERSION $CREATE_QUERY $ITYPES);

$VERSION = '0.1000';
@ISA = qw(SNMP::Monitor::Event);

$CREATE_QUERY = <<'QUERY';
CREATE TABLE SNMPMON_IFLOAD (
  HOST VARCHAR(10) NOT NULL,
  INTERFACE SMALLINT NOT NULL,
  INTERVAL_END DATETIME NOT NULL,
  INOCTETS INT NOT NULL,
  OUTOCTETS INT NOT NULL,
  UTILIZATION REAL NOT NULL,
  ADMINSTATUS TINYINT NOT NULL,
  OPERSTATUS TINYINT NOT NULL,
  INDEX (HOST, INTERFACE, INTERVAL_END)
)
QUERY

$ITYPES = [
#   Interface type              Full-Duplex
    undef,
    [ 'other',                  0 ],
    [ 'regular1822',            1 ],
    [ 'hdh1822',                1 ],
    [ 'ddn-x25',                1 ],
    [ 'rfc877-x25',             1 ],
    [ 'ethernet-csmacd',        0 ],
    [ 'iso88023-csmacd',        0 ],
    [ 'iso88024-tokenBus',      0 ],
    [ 'iso88025-tokenRing',     0 ],
    [ 'iso88026-man',           0 ],
    [ 'starLan',                0 ],
    [ 'proteon-10Mbit',         0 ],
    [ 'proteon-80Mbit',         0 ],
    [ 'hyperchannel',           0 ],
    [ 'fddi',                   0 ],
    [ 'lapb',                   1 ],
    [ 'sdlc',                   1 ],
    [ 'ds1',                    1 ],
    [ 'e1',                     1 ],
    [ 'basicISDN',              1 ],
    [ 'primaryISDN',            1 ],
    [ 'propPointToPointSerial', 1 ],
    [ 'ppp',                    1 ],
    [ 'softwareLoopback',       0 ],
    [ 'eon',                    0 ],
    [ 'ethernet-3Mbit',         0 ],
    [ 'nsip',                   0 ],
    [ 'slip',                   1 ],
    [ 'ultra',                  0 ],
    [ 'ds3',                    1 ],
    [ 'sip',                    1 ],
    [ 'frame-relay',            1 ]
];


sub new ($$$) {
    my($proto, $session, $attr) = @_;
    my $self = $proto->SUPER::new($session, $attr);
    $self->{init_count} = 5;

    my $table = "interfaces.ifTable.ifEntry";
    my $num = $self->{num};
    $self->{vars} = [ SNMP::Varbind->new(["$table.ifDescr", $num]),
		      SNMP::Varbind->new(["$table.ifInOctets", $num]),
		      SNMP::Varbind->new(["$table.ifOutOctets", $num]),
		      SNMP::Varbind->new(["$table.ifSpeed", $num]),
		      SNMP::Varbind->new(["$table.ifType", $num]),
		      SNMP::Varbind->new(["$table.ifAdminStatus", $num]),
		      SNMP::Varbind->new(["$table.ifOperStatus", $num]) ];

    #
    #   Decide whether this is a full duplex interface; code borrowed
    #   from the 'ifload' script of the scotty package by Juergen
    #   Schoenwaelder
    #
    my $type = $self->{'type'};
    if ($type =~ /^(\d+)$/) {
	my $ref = $ITYPES->[$type];
	if (defined($ref)) {
	    $self->{full_duplex} = $ref->[1];
	}
    } else {
	my $ref;
	foreach $ref (@$ITYPES) {
	    if ($ref  &&  $ref->[0] eq $type) {
		$self->{full_duplex} = $ref->[1];
		last;
	    }
	}
    }

    if (!defined($self->{full_duplex})) {
	die "Unknown interface type: $type";
    }

    $self;
}


sub Process ($) {
    my($self) = @_;
    my $session = $self->{session};
    my $dbh = $session->{config}->{dbh};
    my $vr_session = $session->{vars_registered};
    my $vr_self = $self->{vars_registered};

    # The following list corresponds to the list in the 'new' method.
    # This is important when calculation the index $i in $vr_self->[$i].
    my $ifDescr = $vr_session->[$vr_self->[0]]->[0]->[2];
    my $ifInOctets = $vr_session->[$vr_self->[1]]->[0]->[2];
    my $ifOutOctets = $vr_session->[$vr_self->[2]]->[0]->[2];
    my $ifSpeed = $vr_session->[$vr_self->[3]]->[0]->[2];
    my $ifType = $vr_session->[$vr_self->[4]]->[0]->[2];
    my $ifAdminStatus = $vr_session->[$vr_self->[5]]->[0]->[2];
    my $ifOperStatus = $vr_session->[$vr_self->[6]]->[0]->[2];
    my $num = $self->{num};

    if ($self->{description} ne $ifDescr  ||
	$self->{speed} ne $ifSpeed        ||
	$self->{type} ne $ifType) {
	if (!$self->{err_msg_mismatch}) {
	    my $cDescr = $self->{description};
	    my $cSpeed = $self->{speed};
	    my $cType = $self->{type};
	    $self->{err_msg_mismatch} =
		$self->Message(subject => 'Router config mismatch',
			       body => <<"MSG");

The configuration of interface $num doesn't match the detected parameters.
The configured parameters are:

    Interface description:  $cDescr
    Interface speed:        $cSpeed
    Interface type:         $cType

The detected parameters are:

    Interface description:  $ifDescr
    Interface speed:        $ifSpeed
    Interface type:         $ifType

I won't send further messages until the configured parameters match or
the SNMP::Monitor is restarted.

MSG
        }
    } else {
	$self->{err_msg_mismatch} = 0;
    }

    my $time = $session->{'time'};
    my $oldTime = $self->{'time'};
    $self->{'time'} = $time;

    my $oldIfInOctets = $self->{ifInOctets};
    $self->{ifInOctets} = $ifInOctets;
    if (defined($oldIfInOctets)  &&  $ifInOctets > $oldIfInOctets) {
	$ifInOctets -= $oldIfInOctets;
    } else {
	$ifInOctets = 0;
    }

    my $oldIfOutOctets = $self->{ifOutOctets};
    $self->{ifOutOctets} = $ifOutOctets;
    if (defined($oldIfOutOctets)  &&  $ifOutOctets > $oldIfOutOctets) {
	$ifOutOctets -= $oldIfOutOctets;
    } else {
	$ifOutOctets = 0;
    }

    my $utilization;
    if ($ifInOctets > 0  ||  $ifOutOctets > 0) {
	my $delta;
	if ($self->{full_duplex}) {
	    $delta = ($ifInOctets > $ifOutOctets) ? $ifInOctets : $ifOutOctets;
	} else {
	    $delta = $ifInOctets + $ifOutOctets;
	}
	$utilization = ($delta * 8 * 100.0) / (($time - $oldTime) * $ifSpeed);
    } else {
	$utilization = 0.0;
    }

    if ($session->{config}->{debug}) {
        Sys::Syslog::syslog('debug',
			    "IfLoad: Host %s, interface %d: InOctets %s => %d,"
			    . " OutOctets %s => %d",
			    $session->{name}, $self->{num},
			    defined($oldIfInOctets) ? $oldIfInOctets : "undef",
			    $ifInOctets,
			    defined($oldIfOutOctets) ?
			        $oldIfOutOctets : "undef",
			    $ifOutOctets);
    }

    if (!$dbh->do("INSERT INTO SNMPMON_IFLOAD VALUES (?, ?, FROM_UNIXTIME(?),"
		  . " ?, ?, ?, ?, ?)",
		  undef, $session->{name}, $num, $session->{'time'},
		  $ifInOctets, $ifOutOctets, $utilization, $ifAdminStatus,
		  $ifOperStatus)) {
	my $errmsg = $dbh->errstr();
	my $host = $session->{name};

	$self->Message(subject => 'Database error',
		       body => <<"MSG")

A database error occurred, while logging the following values:

    Host name:         $host
    Interface number:  $num
    Time:              $time
    InOctets:          $ifInOctets
    OutOctets:         $ifOutOctets
    Utilization:       $utilization
    AdminStatus:       $ifAdminStatus
    OperStatus:        $ifOperStatus

The database error message was:

$errmsg

I will send another message for any following database error, so that you
can add the entry later.

MSG
    }
}


1;
