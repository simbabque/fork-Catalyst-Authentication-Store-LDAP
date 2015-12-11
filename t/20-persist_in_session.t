#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Catalyst::Authentication::Store::LDAP::Backend;
use lib 't/lib';
use LDAPTest;

my $server = LDAPTest::spawn_server();

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
is($user->for_session, 'somebody', 'persist_in_session unset: for_session ok');

my $back_persist_username = Catalyst::Authentication::Store::LDAP::Backend->new(
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
$user = $back_persist_username->find_user( { username => 'somebody' } );
is($user->for_session, 'somebody',
    "persist_in_session 'username': for_session ok");

my $back_persist_all = Catalyst::Authentication::Store::LDAP::Backend->new(
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
$user = $back_persist_all->find_user( { username => 'somebody' } );
is_deeply($user->for_session,
    {
        persist_in_session => 'all',
        user => $user->user,
        _roles => [],
    },
    "persist_in_session 'all': for_session ok");

done_testing;
