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
    my ($self, $email) = @_;
    
    $email = escape_filter_value($email);
	
	my $base_dn = Bugzilla->params->{"LDAPBaseDN"};
	my $uid_attr = Bugzilla->params->{"LDAPuidattribute"};
	my $mail_attr = Bugzilla->params->{"LDAPmailattribute"};
	my @attrs = ($uid_attr);
	my $mail_result = $self->ldap->search(( base   => $base_dn,
								      scope  => "sub",
									  filter => "(&($mail_attr=$email))"),
									  attrs  => \@attrs);
									  
	my $uid =  $mail_result->entry->get_value($uid_attr);
    
	my $base_group_dn = Bugzilla->params->{"LDAPgroupbaseDN"};
	my $gid_attr = Bugzilla->params->{"LDAPgidattribute"};
	# I don't understand references... so yeah, this works and I'm sure its dumb.
	@attrs = ($gid_attr);
    my $dn_result = $self->ldap->search(( base   => $base_group_dn,
                                          scope  => 'sub',
                                          filter => "(&($uid_attr=$uid))"),
                                          attrs => \@attrs );

    if ($dn_result->code) {
        ThrowCodeError('ldap_search_error',
            { errstr => $dn_result->error, username => $uid });
    }
	
	my @ldap_group_dns;
    push @ldap_group_dns, $gid_attr."=".$_->get_value($gid_attr) for $dn_result->entries;
	
	#my $infoString = "uid:".$uid." uid_attr:".$uid_attr." base_dn:".$base_dn." base_group_dn:".$base_group_dn.
	#				 "\ndn_result->count:".$dn_result->count.
	#				 "\n".join(",",@ldap_group_dns);

	#ThrowCodeError('ldap_search_error', { errstr => $infoString, username => $uid });
    return \@ldap_group_dns;
}

1;
