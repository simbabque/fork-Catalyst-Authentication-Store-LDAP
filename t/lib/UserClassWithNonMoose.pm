package UserClassWithNonMoose;
use Moose;
use MooseX::NonMoose;
extends 'Catalyst::Authentication::Store::LDAP::User';

sub my_method {
    return 'frobnitz';
}

sub BUILDARGS { +{} }

1;
