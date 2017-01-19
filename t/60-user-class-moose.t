#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 't/lib';
use LDAPTest;
use Storable qw/ freeze /;
use Test::Exception;
use Test::Needs 'Moose', 'MooseX::NonMoose';

my $server = LDAPTest::spawn_server();

use_ok("Catalyst::Authentication::Store::LDAP::Backend");

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
        'user_class' => 'UserClassWithNonMoose',
    }
);

isa_ok( $back, "Catalyst::Authentication::Store::LDAP::Backend" );

my $user;
lives_ok { $user = $back->find_user( { username => 'somebody' } ) } 'No weird MooseX::NonMoose exceptions';

isa_ok( $user, "Catalyst::Authentication::Store::LDAP::User" );
isa_ok( $user, "UserClassWithNonMoose");

is( $user->my_method, 'frobnitz', "methods on user class work" );

# RT 69615
diag("stop() server");
$server->stop();

$server = LDAPTest::spawn_server();

lives_and { ok $user->check_password('foo') } 'Can check correct password';
lives_and { ok $user->check_password('bar') } 'Can check wrong password';

my $frozen_user;
lives_ok { $frozen_user = freeze $user } 'Can freeze user with Storable';
ok $frozen_user, 'is frozen';

# RT 69615
diag("stop() server");
$server->stop();

done_testing;

