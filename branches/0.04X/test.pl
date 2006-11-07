#!/usr/bin/perl
#
# test.pl for sFlow.pm
#
# Elisa Jasinska <elisa.jasinska@ams-ix.net>
# 2006/08/08
#

use Test::More tests => 2;

BEGIN { use_ok( 'Net::sFlow' ); } 
BEGIN { use_ok( 'Math::BigInt' ); }
