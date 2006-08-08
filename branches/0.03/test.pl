#!/usr/bin/perl
#
# test.pl for sFlow.pm
#
# Elisa Jasinska <elisa.jasinska@ams-ix.net>
# 2006/07/27
#

use Test::More tests => 4;

BEGIN { use_ok( 'Net::sFlow' ); } 
BEGIN { use_ok( 'Math::BigInt' ); }
BEGIN { use_ok( 'Net::IP' ); }
BEGIN { use_ok( 'NetPacket' ); }
