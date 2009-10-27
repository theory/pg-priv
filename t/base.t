#!/usr/bin/env perl -w

use strict;
use warnings;
use Test::More tests => 1;

my $CLASS;
BEGIN {
    $CLASS = 'Pg::Priv';
    use_ok $CLASS or die;
}
