# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.
#

package Bugzilla::Extension::LDAPGroups::Auth::Verify::LDAP;
use strict;
use parent qw(Bugzilla::Auth::Verify::LDAP);

use Bugzilla::Error qw(ThrowCodeError);

use Net::LDAP;
use Net::LDAP::Util qw(escape_filter_value);


sub check_credentials {
    my ($self, $params) = @_;
    $params = $self->SUPER::check_credentials($params);
    return $params if $params->{failure};
    my $ldap_group_dns = $self->_ldap_member_of_groups($params->{bz_username});
    $params->{ldap_group_dns} = $ldap_group_dns if scalar @$ldap_group_dns;
    return $params;
}

sub _ldap_member_of_groups {
    my ($self, $uid) = @_;
	
	if ($uid =~ m/(.*?)\@/) {
		$uid = $1;
	}
    $uid = escape_filter_value($uid);

    my $uid_attr = Bugzilla->params->{"LDAPuidattribute"};
    my $base_dn = Bugzilla->params->{"LDAPBaseDN"};
	
	# Get the user's cn so we can build the dn. This
	# is probably a stupid way to do things. -Dave 06/24/2014
	my $dn_user_result = $self->ldap->search(( base   => $base_dn,
											   scope  => 'sub',
										       filter => "$uid_attr=$uid"),
											   attrs => ['*']
										    );
	if ($dn_user_result->code) {
		ThrowCodeError('ldap_search_error',
			{ errstr => $dn_user_result->error, username => $uid });
	}
	
	my $entry = $dn_user_result->entry;
	
	# TODO - Delete this array, it is pointless - Dave
	#my @arr;
	#push @arr, $_->get_value("cn") for $dn_user_result->entries;
	
	my $user_dn = "cn=" . $dn_user_result->entry->get_value('cn') . ',' . $base_dn;
	
	my $base_group_dn = "ou=crews,ou=groups,o=sevenSeas";
    my $dn_result = $self->ldap->search( base   => $base_group_dn,
                                          scope  => 'sub',
                                          filter => "(&(objectclass=groupOfUniqueNames) (uniquemember=$user_dn))" );

    if ($dn_result->code) {
        ThrowCodeError('ldap_search_error',
            { errstr => $dn_result->error, username => $uid });
    }
	
	my @ldap_group_dns;
    push @ldap_group_dns, "cn=".$_->get_value('cn').",".$base_group_dn for $dn_result->entries;
	
	#my $infoString = "uid:".$uid." uid_attr:".$uid_attr." user_dn:".$user_dn." base_dn:".$base_dn.
	#				 "\ndn_user_result->count:".$dn_user_result->count." dn_result->count:".$dn_result->count.
	#				 "\n".join(",",@ldap_group_dns);
    
	#ThrowCodeError('ldap_search_error', { errstr => $infoString, username => $uid });
    return \@ldap_group_dns;
}

1;
