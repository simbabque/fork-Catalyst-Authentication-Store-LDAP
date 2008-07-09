# local test ldap server

package LDAPTest;

use Net::LDAP::Server::Test;
use Net::LDAP::Entry;

sub server_port {10636}
sub server_host { 'ldap://127.0.0.1:' . server_port() }

sub spawn_server {
    my @mydata;
    my $entry = Net::LDAP::Entry->new;
    $entry->dn('ou=foobar');
    $entry->add(
        dn          => 'ou=foobar',
        uid         => 'somebody',
        displayName => 'Some Body',
        cn          => [qw(value1 value2)]
    );
    push @mydata, $entry;

    return Net::LDAP::Server::Test->new( server_port(), data => \@mydata );
}

1;
