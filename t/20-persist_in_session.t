#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Catalyst::Authentication::Store::LDAP::Backend;
use lib 't/lib';
use LDAPTest;

my $server = LDAPTest::spawn_server();

# the tests  currently don't require a real Catalyst app instance
my $c;

subtest "persist_in_session unset" => sub {
    my $back = Catalyst::Authentication::Store::LDAP::Backend->new(
        {   'ldap_server' => LDAPTest::server_host(),
            'binddn'      => 'anonymous',
            'bindpw'      => 'dontcarehow',
            'start_tls'   => 0,
            'user_basedn' => 'ou=foobar',
            'user_filter' => '(&(objectClass=person)(uid=%s))',
            'user_scope'  => 'one',
            'user_field'  => 'uid',
            'use_roles'   => 0,
        }
    );

    my $user = $back->find_user( { username => 'somebody' } );
    ok( my $session = $user->for_session, 'for_session ok');
    is($session, 'somebody', 'for_session returns correct data');
    ok($back->from_session($c, $session), 'from_session ok');
};

subtest "persist_in_session 'username'" => sub {
    my $back = Catalyst::Authentication::Store::LDAP::Backend->new(
        {   ldap_server         => LDAPTest::server_host(),
            binddn              => 'anonymous',
            bindpw              => 'dontcarehow',
            start_tls           => 0,
            user_basedn         => 'ou=foobar',
            user_filter         => '(&(objectClass=person)(uid=%s))',
            user_scope          => 'one',
            user_field          => 'uid',
            use_roles           => 0,
            persist_in_session  => 'username',
        }
    );
    my $user = $back->find_user( { username => 'somebody' } );
    ok( my $session = $user->for_session, 'for_session ok');
    is($session, 'somebody', 'for_session returns correct data');
    ok($back->from_session($c, $session), 'from_session ok');
};

subtest "persist_in_session 'all'" => sub {
    my $back = Catalyst::Authentication::Store::LDAP::Backend->new(
        {   ldap_server         => LDAPTest::server_host(),
            binddn              => 'anonymous',
            bindpw              => 'dontcarehow',
            start_tls           => 0,
            user_basedn         => 'ou=foobar',
            user_filter         => '(&(objectClass=person)(uid=%s))',
            user_scope          => 'one',
            user_field          => 'uid',
            use_roles           => 0,
            persist_in_session  => 'all',
        }
    );
    my $user = $back->find_user( { username => 'somebody' } );
    ok( my $session = $user->for_session, 'for_session ok');
    is_deeply($session,
        {
            persist_in_session => 'all',
            user => $user->user,
            _roles => [],
        },
        "for_session returns correct data");
    ok($back->from_session($c, $session), 'from_session ok');
};

done_testing;
