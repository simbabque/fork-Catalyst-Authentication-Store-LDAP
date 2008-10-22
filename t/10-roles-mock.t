#!/usr/bin/perl

use strict;
use warnings;
use Catalyst::Exception;

use Test::More tests => 7;
use Test::MockObject::Extends;
use Net::LDAP::Entry;
use lib 't/lib';

SKIP: {

    eval "use Catalyst::Model::LDAP";
    if ($@) {
        skip "Catalyst::Model::LDAP not installed", 7;
    }

    use_ok("Catalyst::Authentication::Store::LDAP::Backend");

    my (@searches, @binds);
    for my $i (0..1) {

        my $back = Catalyst::Authentication::Store::LDAP::Backend->new({
            'ldap_server' => 'ldap://127.0.0.1:555',
            'binddn'      => 'anonymous',
            'bindpw'      => 'dontcarehow',
            'start_tls'   => 0,
            'user_basedn' => 'ou=foobar',
            'user_filter' => '(&(objectClass=inetOrgPerson)(uid=%s))',
            'user_scope'  => 'one',
            'user_field'  => 'uid',
            'use_roles'   => 1,
            'role_basedn' => 'ou=roles',
            'role_filter' => '(&(objectClass=posixGroup)(memberUid=%s))',
            'role_scope'  => 'one',
            'role_field'  => 'userinrole',
            'role_value'  => 'cn',
            'role_search_as_user' => $i,
        });
        $back = Test::MockObject::Extends->new($back);
        my $bind_msg = Test::MockObject->new;
        $bind_msg->mock(is_error => sub {}); # Cause bind call to always succeed
        my $ldap = Test::MockObject->new;
        $ldap->mock('bind', sub { shift; push (@binds, [@_]); return $bind_msg});
        $ldap->mock('unbind' => sub {});
        $ldap->mock('disconnect' => sub {});
        my $search_res = Test::MockObject->new();
        $search_res->mock(is_error => sub {}); # Never an error
        $search_res->mock(entries => sub {
            return map 
                {   my $id = $_; 
                    Test::MockObject->new->mock(
                        get_value => sub { "quux$id" }
                    ) 
                }
                qw/one two/
        });
        my @user_entries;
        $search_res->mock(pop_entry => sub { return pop @user_entries });
        $ldap->mock('search', sub { shift; push(@searches, [@_]); return $search_res; });
        $back->mock('ldap_connect' => sub { $ldap });
        my $user_entry = Net::LDAP::Entry->new;
        push(@user_entries, $user_entry);
        $user_entry->dn('ou=foobar');
        $user_entry->add(
            uid => 'somebody',
            cn => 'test',
        );
        my $user = $back->find_user( { username => 'somebody' } );
        isa_ok( $user, "Catalyst::Authentication::Store::LDAP::User" );
        $user->check_password('password');
        is_deeply( [sort $user->roles], 
                   [sort qw/quuxone quuxtwo/], 
                    "User has the expected set of roles" );
    }
    is_deeply(\@searches, [ 
        ['base', 'ou=foobar', 'filter', '(&(objectClass=inetOrgPerson)(uid=somebody))', 'scope', 'one'],
        ['base', 'ou=roles', 'filter', '(&(objectClass=posixGroup)(memberUid=test))', 'scope', 'one', 'attrs', [ 'userinrole' ]],
        ['base', 'ou=foobar', 'filter', '(&(objectClass=inetOrgPerson)(uid=somebody))', 'scope', 'one'],
        ['base', 'ou=roles', 'filter', '(&(objectClass=posixGroup)(memberUid=test))', 'scope', 'one', 'attrs', [ 'userinrole' ]],
    ], 'User searches as expected');
    is_deeply(\@binds, [
        [ undef ], # First user search
        [
            'ou=foobar',
            'password',
            'password'
        ], # Rebind to confirm user
        [
            undef
        ], # Rebind with initial credentials to find roles
        # 2nd pass round main loop
        [  undef ], # First user search
        [
            'ou=foobar',
            'password',
            'password'
        ] # Rebind to confirm user _and_ lookup roles;
    ], 'Binds as expected');
}
