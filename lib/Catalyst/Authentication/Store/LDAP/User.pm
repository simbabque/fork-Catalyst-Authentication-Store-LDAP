
=pod

=head1 NAME

Catalyst::Authentication::Store::LDAP::User
 - A User object representing an LDAP object. 

=head1 SYNOPSIS

You should be creating these objects through L<Catalyst::Authentication::Store::LDAP::Backend>'s "get_user" method, or just letting $c->login do
it for you.

    sub action : Local {
        my ( $self, $c ) = @_;
        $c->login($c->req->param(username), $c->req->param(password));
        $c->log->debug($c->user->username . "is really neat!");
    }

If you access just $c->user in a scalar context, it will return the current
username.

=head1 DESCRIPTION

This wraps up an LDAP object and presents a simplified interface to it's
contents.  It uses some AUTOLOAD magic to pass method calls it doesn't
understand through as simple read only accessors for the LDAP entries
various attributes.  

It gets grumpy if you ask for an attribute via the AUTOLOAD mechanism
that it doesn't know about.  Avoid that with using "has_attribute", 
discussed in more detail below.

You can skip all that and just go straight to the L<Net::LDAP::Entry>
object through the "ldap_entry" method:

    my $entry = $c->user->ldap_entry;

It also has support for Roles.

=cut

package Catalyst::Authentication::Store::LDAP::User;
use base qw( Catalyst::Authentication::User Class::Accessor::Fast );

use strict;
use warnings;

our $VERSION = '0.1002';

BEGIN { __PACKAGE__->mk_accessors(qw/user store/) }

use overload '""' => sub { shift->stringify }, fallback => 1;

=head1 METHODS

=head2 new($store, $user)

Takes a L<Catalyst::Authentication::Store::LDAP::Backend> object
as $store, and the data structure returned by that class's "get_user"
method as $user.

Returns a L<Catalyst::Authentication::Store::LDAP::User> object.

=cut

sub new {
    my ( $class, $store, $user ) = @_;

    return unless $user;

    bless { store => $store, user => $user, }, $class;
}

=head2 id

Returns the results of the "stringify" method.

=cut

sub id {
    my $self = shift;
    return $self->stringify;
}

=head2 stringify

Uses the "user_field" configuration option to determine what the "username"
of this object is, and returns it.

If you use the special value "dn" for user_field, it will return the DN
of the L<Net::LDAP::Entry> object.

=cut

sub stringify {
    my ($self) = @_;
    my $userfield = $self->store->user_field;
    $userfield = $$userfield[0] if ref $userfield eq 'ARRAY';
    if ( $userfield eq "dn" ) {
        my ($string) = $self->user->ldap_entry->dn;
        return $string;
    }
    else {
        my ($string) = $self->$userfield;
        return $string;
    }
}

=head2 supported_features

Returns hashref of features that this Authentication::User subclass supports.

=cut

sub supported_features {
    return {
        password => { self_check => 1, },
        session  => 1,
        roles    => { self_check => 0, },
    };
}

=head2 check_password($password)

Bind's to the directory as the DN of the internal L<Net::LDAP::Entry> object,
using the bind password supplied in $password.  Returns 1 on a successful
bind, 0 on failure.

=cut

sub check_password {
    my ( $self, $password ) = @_;
    my $ldap
        = $self->store->ldap_bind( undef, $self->ldap_entry->dn, $password,
        'forauth' );
    if ( defined($ldap) ) {
        return 1;
    }
    else {
        return 0;
    }
}

=head2 roles

Returns the results of L<Catalyst::Authentication::Store::LDAP::Backend>'s "lookup_roles" method, an array of roles that are valid for this user.

=cut

sub roles {
    my $self = shift;
    return $self->store->lookup_roles($self);
}

=head2 for_session

Returns the User object, stringified.

=cut

sub for_session {
    my $self = shift;
    return $self->stringify;
}

=head2 ldap_entry

Returns the raw ldap_entry. 

=cut

sub ldap_entry {
    my $self = shift;
    return $self->user->{'ldap_entry'};
}

=head2 attributes($type)

Returns an array of attributes present for this user.  If $type is "ashash",
it will return a hash with the attribute names as keys. (And the values of
those attributes as, well, the values of the hash)

=cut

sub attributes {
    my ( $self, $type ) = @_;
    if ( $type eq "ashash" ) {
        return $self->user->{'attributes'};
    }
    else {
        return keys( %{ $self->user->{'attributes'} } );
    }
}

=head2 has_attribute

Returns the values for an attribute, or undef if that attribute is not present.
The safest way to get at an attribute. 

=cut

sub has_attribute {
    my ( $self, $attribute ) = @_;
    if ( !defined($attribute) ) {
        Catalyst::Exception->throw(
            "You must provide an attribute to has_attribute!");
    }
    if ( $attribute eq "dn" ) {
        return $self->ldap_entry->dn;
    }
    elsif ( exists( $self->user->{'attributes'}->{$attribute} ) ) {
        return $self->user->{'attributes'}->{$attribute};
    }
    else {
        return undef;
    }
}

=head2 AUTOLOADed methods

We automatically map the attributes of the underlying L<Net::LDAP::Entry>
object to read-only accessor methods.  So, if you have an entry that looks
like this one:

    dn: cn=adam,ou=users,dc=yourcompany,dc=com
    cn: adam
    loginShell: /bin/zsh
    homeDirectory: /home/adam
    gecos: Adam Jacob
    gidNumber: 100
    uidNumber: 1053
    mail: adam@yourcompany.com
    uid: adam
    givenName: Adam
    sn: Jacob
    objectClass: inetOrgPerson
    objectClass: organizationalPerson
    objectClass: Person
    objectClass: Top
    objectClass: posixAccount

You can call:

    $c->user->homedirectory

And you'll get the value of the "homeDirectory" attribute.  Note that
all the AUTOLOADed methods are automatically lower-cased. 

=head2 Special Keywords

The highly useful and common method "username" will map to the configured
value of user_field (uid by default.) 

    $c->user->username == $c->user->uid

=cut

sub AUTOLOAD {
    my $self = shift;

    ( my $method ) = ( our $AUTOLOAD =~ /([^:]+)$/ );

    if ( $method eq "DESTROY" ) {
        return;
    }
    if ( exists( $self->user->{'attributes'}->{$method} ) ) {
        return $self->user->{'attributes'}->{$method};
    }
    elsif ( $method eq "username" ) {
        my $userfield = $self->store->user_field;
        my $username  = $self->has_attribute($userfield);
        if ($username) {
            return $username;
        }
        else {
            Catalyst::Exception->throw( "User is missing the "
                    . $userfield
                    . " attribute, which should not be possible!" );
        }
    }
    else {
        Catalyst::Exception->throw(
            "No attribute $method for User " . $self->stringify );
    }
}

1;

__END__

=head1 AUTHORS

Adam Jacob <holoway@cpan.org>

Some parts stolen shamelessly and entirely from
L<Catalyst::Plugin::Authentication::Store::Htpasswd>. 

Currently maintained by Peter Karman <karman@cpan.org>.

=head1 THANKS

To nothingmuch, ghenry, castaway and the rest of #catalyst for the help. :)

=head1 SEE ALSO

L<Catalyst::Authentication::Store::LDAP>, L<Catalyst::Authentication::Store::LDAP::Backend>, L<Catalyst::Plugin::Authentication>, L<Net::LDAP>

=head1 COPYRIGHT & LICENSE

Copyright (c) 2005 the aforementioned authors. All rights
reserved. This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut

