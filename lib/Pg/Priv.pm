package Pg::Priv;

use 5.6.2;
use strict;
use warnings;

our $VERSION = '0.10';

my %label_for = (
    r => 'SELECT',
    w => 'UPDATE',
    a => 'INSERT',
    d => 'DELETE',
    D => 'TRUNCATE',
    x => 'REFERENCE',
    t => 'TRIGGER',
    X => 'EXECUTE',
    U => 'USAGE',
    C => 'CREATE',
    c => 'CONNECT',
    T => 'TEMPORARY',
);

my %priv_for = map { $label_for{$_} => $_ } keys %label_for;

# Some aliases.
$priv_for{TEMP} = 'T';

sub parse_acl {
    my ($class, $acl, $quote) = @_;
    return unless $acl;

    my @privs;
    my $prev;
    for my $perms (@{ $acl }) {
        # http://www.postgresql.org/docs/current/static/sql-grant.html#SQL-GRANT-NOTES
        my ($role, $privs, $by) = $perms =~ m{^"?(?:(?:group\s+)?([^=]+))?=([^/]+)/(.*)};
        $prev = $privs eq '*' ? $prev : $privs;
        $role ||= 'public';
        push @privs, $class->new(
            role  => $quote ? _quote_ident($role) : $role,
            by    => $quote ? _quote_ident($by)   : $by,
            privs => $prev,
        )
    }
    return wantarray ? @privs : \@privs;
}

sub new {
    my $class = shift;
    my $self = bless { @_ } => $class;
    $self->{parsed} = { map { $_ => 1 } split //, $self->{privs} || '' };
    return $self;
}

sub role  { shift->{role}  }
sub by    { shift->{by}    }
sub privs { shift->{privs} }
sub labels {
    wantarray ? map { $label_for{$_} } keys %{ shift->{parsed} }
              : [ map { $label_for{$_} } keys %{ shift->{parsed} } ];
}
sub can   {
    my $can = shift->{parsed} or return;
    for my $what (@_) {
        return unless $can->{ length $what == 1 ? $what : $priv_for{uc $what} };
    }
    return 1;
}

sub can_select    { shift->can('r') }
sub can_read      { shift->can('r') }
sub can_update    { shift->can('w') }
sub can_write     { shift->can('w') }
sub can_insert    { shift->can('a') }
sub can_append    { shift->can('a') }
sub can_delete    { shift->can('d') }
sub can_reference { shift->can('x') }
sub can_trigger   { shift->can('t') }
sub can_execute   { shift->can('X') }
sub can_usage     { shift->can('U') }
sub can_create    { shift->can('C') }
sub can_connect   { shift->can('c') }
sub can_temporary { shift->can('T') }
sub can_temp      { shift->can('T') }

# ack ' RESERVED_KEYWORD' src/include/parser/kwlist.h | awk -F '"' '{ print "    " $2 }'
my %reserved = ( map { $_ => undef } qw(
    all
    analyse
    analyze
    and
    any
    array
    as
    asc
    asymmetric
    both
    case
    cast
    check
    collate
    column
    constraint
    create
    current_catalog
    current_date
    current_role
    current_time
    current_timestamp
    current_user
    default
    deferrable
    desc
    distinct
    do
    else
    end
    except
    false
    fetch
    for
    foreign
    from
    grant
    group
    having
    in
    initially
    intersect
    into
    leading
    limit
    localtime
    localtimestamp
    new
    not
    null
    off
    offset
    old
    on
    only
    or
    order
    placing
    primary
    references
    returning
    select
    session_user
    some
    symmetric
    table
    then
    to
    trailing
    true
    union
    unique
    user
    using
    variadic
    when
    where
    window
    with
));

sub _is_reserved($) {
    exists $reserved{+shift};
}

sub _quote_ident($) {
    my $role = shift;
    # Can avoid quoting if ident starts with a lowercase letter or underscore
    # and contains only lowercase letters, digits, and underscores, *and* is
    # not any SQL keyword. Otherwise, supply quotes.
    return $role if $role =~ /^[_a-z](?:[_a-z0-9]+)?$/ && !_is_reserved $role;
    $role =~ s/"/""/g;
    return qq{"$role"};
}

1;
__END__

##############################################################################

=begin comment

Fake-out Module::Build. Delete if it ever changes to support =head1 headers
other than all uppercase.

=head1 NAME

Pg::Priv - PostgreSQL ACL parser and iterator

=end comment

=head1 Name

Pg::Priv - PostgreSQL ACL parser and iterator

=head1 Synopsis

  use DBI;
  use Pg::Priv;

  my $dbh = DBI->connect('dbi:Pg:dbname=template1', 'postgres', '');
  my $sth = $dbh->prepare(
      q{SELECT relname, relacl FROM pg_class WHERE relkind = 'r'}
  );

  $sth->execute;
  while (my $row = $sth->fetchrow_hashref) {
      print "Table $row->{relname}:\n";
      for my $priv ( Pg::Priv->parse_acl( $row->{relacl} ) ) {
          print '    ', $priv->by, ' granted to ', $priv->role, ': ',
              join( ', ', $priv->labels ), $/;
      }
  }

=head1 Description

This module parses PostgreSQL ACL strings and represents the underlying
privileges as objects. Use accessors on the objects to see what privileges are
granted by whom and to whom.

=head1 Interface

=head2 Class Methods

=head3 parse_acl

  for my $priv ( Pg::Priv->parse_acl($acl) ) {
      print '    ', $priv->by, ' granted to ', $priv->role, ': ',
          join( ', ', $priv->labels ), $/;
  }

Takes a PostgreSQL ACL string, parsers it, and returns a list or array
reference of Pg::Priv objects. Pass an optional second argument to specify
that role names should be quoted as identifiers (i.e., like the PostgreSQL
C<quote_ident()> function does.

=head2 Constructor

=head3 new

  my $priv = Pg::Priv->new(
      role  => $role,
      by    => $by,
      privs => $priv,
  );

Constructs and returns a Pg::Priv object for the given grantor, grantee, and
privileges. The C<privs> parameter is a string representing the privileges,
such as C<arwdxt>. If you're fetching ACLs from PostgreSQL, you're more likely
to want C<parse_acl()>, which will figure this stuff out for you.

=head2 Instance Methods

=head3 C<role>

Returns the name of the role that has the privileges (the grantee).

=head3 C<by>

Returns the name of the role that granted the privileges (the grantor).

=head3 C<privs>

A string representing the privileges granted, such as C<arwdxt>.

=head3 C<labels>

A list or array reference of the labels for the granted privileges.

=head3 C<can>

  print $priv->role can', ($priv->can('r') ? '' : 'not'), ' SELECT';
  print $priv->role can', ($priv->can('UPDATE') ? '' : 'not'), ' UPDATE';

Pass in a permission character or label and this method will return true if
that privilege is included.

=head3 C<can_select>

Returns true if the SELECT privilege has been granted.

=head3 C<can_read>

Returns true if the SELECT privilege has been granted.

=head3 C<can_update>

Returns true if the UPDATE privilege has been granted.

=head3 C<can_write>

Returns true if the UPDATE privilege has been granted.

=head3 C<can_insert>

Returns true if the INSERT privilege has been granted.

=head3 C<can_append>

Returns true if the INSERT privilege has been granted.

=head3 C<can_delete>

Returns true if the DELETE privilege has been granted.

=head3 C<can_reference>

Returns true if the REFERENCE privilege has been granted.

=head3 C<can_trigger>

Returns true if the TRIGGER privilege has been granted.

=head3 C<can_execute>

Returns true if the EXECUTE privilege has been granted.

=head3 C<can_usage>

Returns true if the USAGE privilege has been granted.

=head3 C<can_create>

Returns true if the CREATE privilege has been granted.

=head3 C<can_connect>

Returns true if the CONNECT privilege has been granted.

=head3 C<can_temporary>

Returns true if the TEMPORARY privilege has been granted.

=head3 C<can_temp>

Returns true if the TEMPORARY privilege has been granted.

=head1 Author

=begin comment

Fake-out Module::Build. Delete if it ever changes to support =head1 headers
other than all uppercase.

=head1 AUTHOR

=end comment

=head1 Author

David E. Wheeler <david@justatheory.com>

=head1 Copyright and License

Copyright (c) 2009 Etsy, Inc. Some Rights Reserved.

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
