#!/usr/bin/perl
#
# test.pl for sFlow.pm
#
# Elisa Jasinska <elisa@jasinska.de>
# 12/16/2014
#

use Test::More qw(no_plan);

BEGIN { use_ok( 'Net::sFlow' ); } 
BEGIN { use_ok( 'Math::BigInt' ); }
