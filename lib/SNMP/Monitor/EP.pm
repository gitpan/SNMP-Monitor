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

require 5.004;
use strict;


require SNMP::Monitor;


package SNMP::Monitor::EP;

@SNMP::Monitor::EP::ISA = qw(HTML::EP);

sub init ($) {
    my($self) = @_;
    $self->{_ep_funcs}->{'ep-snmpmon-auth'} = { method => 'snmpmon_auth' };
    $self;
}


sub _snmpmon_auth_interface ($$$$) {
    my($self, $interface_ref, $host_ref, $user) = @_;

    my($u, $config);
    foreach $config ($interface_ref->{'users'},
		     $host_ref->{'users'},
		     $self->{'snmpmon_config'}->{'users'}) {
	if ($config) {
	    foreach $u (@$config) {
		if ($u eq $user) {
		    return $interface_ref;
		}
	    }
	    return undef;
	}
    }
    return $interface_ref;
}


sub snmpmon_auth ($$;$) {
    my($self, $attr, $func) = @_;

    if (!$self->{snmpmon_config}) {
	if (!$attr->{configuration}) {
	    die "Missing config file";
	}
	$self->{snmpmon_config} =
	    SNMP::Monitor->Configuration($attr->{configuration});
    }
    my $config = $self->{snmpmon_config};


    my $user = $self->{env}->{REMOTE_USER};
    if (!$user) {
	if (!exists($attr->{'user'})) {
	    die "Not authorized as any user";
	}
	$user = $attr->{'user'};
    }

    my $ilist = [];
    if ($attr->{interface}) {
	# Authenticate for displaying this interface
	# Host must be given!
	if ($attr->{interface} =~ /(.+)\:(.*)/) {
	    my $host = $1;
	    my $interface = $2;
	    my $host_ref = $config->{hosts}->{$host};
	    if (!$host_ref) {
		die "No such host: $host";
	    }
	    my $interface_ref;
	    foreach $interface_ref (@{$host_ref->{interfaces}}) {
		if ($interface_ref->{num} eq $interface) {
		    if ($self->_snmpmon_auth_interface($interface_ref,
						       $host_ref,
						       $user)) {
			push(@$ilist, { host => $host_ref,
					interface => $interface_ref});
			last;
		    } else {
			die "Not authorized for interface $interface at"
			    . " host $host";
		    }
		}
	    }
	    if (!@$ilist) {
		die "No such interface for host $host: $interface";
	    }
	}
    } else {
	# Authenticate for displaying any interface
	my($host_ref, $interface_ref);
	foreach $host_ref (values(%{$config->{hosts}})) {
	    foreach $interface_ref (@{$host_ref->{interfaces}}) {
		if ($self->_snmpmon_auth_interface($interface_ref,
						   $host_ref,
						   $user)) {
		    push(@$ilist, { host => $host_ref,
				    interface => $interface_ref});
		}
	    }
	}
    }

    if (!@$ilist) {
	die "Not authorized";
    }

    $self->{snmpmon_interfaces} = $ilist;

    '';
}


1;
