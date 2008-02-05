#!/usr/bin/perl

use strict;
use warnings;
use Catalyst::Exception;

use Test::More tests => 5;
use lib 't/lib';
use LDAPTest;
my $server = LDAPTest::spawn_server();

use_ok("Catalyst::Authentication::Store::LDAP::Backend");

my $back = Catalyst::Authentication::Store::LDAP::Backend->new(
    {   'ldap_server' => LDAPTest::server_host(),

        # can test the timeout SKIP with this
        'ldap_server_options' =>
            { timeout => -1, debug => $ENV{PERL_DEBUG} || 0 },

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

isa_ok( $back, "Catalyst::Authentication::Store::LDAP::Backend" );
ok( my $user = $back->find_user( { username => 'somebody' } ), "find_user" );
isa_ok( $user, "Catalyst::Authentication::Store::LDAP::User" );
my $displayname = $user->displayname;
cmp_ok( $displayname, 'eq', 'Some Body', 'Should be Some Body' );

