# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::LDAPGroups::Util;

use strict;
use base qw(Exporter);
our @EXPORT = qw(
  sync_ldap
  bind_ldap_for_search
);

use Bugzilla;
use Bugzilla::Error;

sub bind_ldap_for_search {
    my $ldap = Bugzilla->ldap;
    my $bind_result;
    if (Bugzilla->params->{"LDAPbinddn"}) {
        my ($LDAPbinddn,$LDAPbindpass) =
            split(":",Bugzilla->params->{"LDAPbinddn"});
        $bind_result =
            $ldap->bind($LDAPbinddn, password => $LDAPbindpass);
    }
    else {
        $bind_result = $ldap->bind();
    }
    ThrowCodeError("ldap_bind_failed", {errstr => $bind_result->error})
        if $bind_result->code;
}

sub sync_ldap {
    my ($group) = @_;
    my $dbh  = Bugzilla->dbh;
    my $ldap = Bugzilla->ldap;

    bind_ldap_for_search();

    my $sth_add = $dbh->prepare("INSERT INTO user_group_map
                                 (user_id, group_id, grant_type, isbless)
                                 VALUES (?, ?, ?, 0)");

    my $sth_del = $dbh->prepare("DELETE FROM user_group_map
                                 WHERE user_id = ? AND group_id = ?
                                 AND grant_type = ? and isbless = 0");

    my $mail_attr = Bugzilla->params->{"LDAPmailattribute"};
    my $base_dn = Bugzilla->params->{"LDAPBaseDN"};
	my $ldap_group_base_dn = Bugzilla->params->{"LDAPgroupbaseDN"};
	my $uid_attr = Bugzilla->params->{"LDAPuidattribute"};
	
	my $group_dn = $group->ldap_dn;
	
    # Search for members of the LDAP group.
    my $filter = "(&($group_dn))";
    my @attrs = ("$uid_attr");
    my $dn_result = $ldap->search(( base   => $ldap_group_base_dn,
                                    scope  => 'sub',
                                    filter => $filter ), 
                                    attrs => \@attrs);
    if ($dn_result->code) {
        ThrowCodeError('ldap_search_error',
            { errstr => $dn_result->error, username => $group->name });
    }

    my @group_member_uids;
    push @group_member_uids, $_->get_value($uid_attr) foreach $dn_result->entries;

	my @group_member_emails;
	@attrs = Bugzilla->params->{"LDAPmailattribute"};
	foreach my $member_uid (@group_member_uids) {
		my $mail_result = $ldap->search(( base   => $base_dn,
										  scope  => "sub",
										  filter => "(&($uid_attr=$member_uid))"),
										  attrs  => \@attrs);
		push @group_member_emails, $_->get_value($mail_attr) foreach $mail_result->entries;
		if ($mail_result->code) {
        	ThrowCodeError('ldap_search_error',
           		{ errstr => $mail_result->error, username => $member_uid });
    	}
	}

	my $users = Bugzilla->dbh->selectall_hashref(
        "SELECT userid, group_id, login_name
         FROM profiles
         LEFT JOIN user_group_map
                ON user_group_map.user_id = profiles.userid
                   AND group_id = ?
                   AND grant_type = ?
                   AND isbless = 0
         WHERE extern_id IS NOT NULL", 
        'userid', undef, ($group->id, Bugzilla::Extension::LDAPGroups->GRANT_LDAP));

    my @added;
    my @removed;
    foreach my $user (values %$users) {
        # User is no longer member of the group.
        if (defined $user->{group_id}
            and !grep { $_ eq $user->{login_name} } @group_member_emails)
        {
            push @removed, $user->{userid};
        }

        # User has been added to the group.
        if (!defined $user->{group_id}
            and grep { $_ eq $user->{login_name} } @group_member_emails)
        {

            push @added, $user->{userid};
        }
    }

    $sth_add->execute($_, $group->id, Bugzilla::Extension::LDAPGroups->GRANT_LDAP) foreach @added;
    $sth_del->execute($_, $group->id, Bugzilla::Extension::LDAPGroups->GRANT_LDAP) foreach @removed;

	#my $infoString = join(",", @added);
	#ThrowCodeError('ldap_search_error', { errstr => $infoString, username => "At End of Sync!" });
 
    return { added => \@added, removed => \@removed };
}

1;
