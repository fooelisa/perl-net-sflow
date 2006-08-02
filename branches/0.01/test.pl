#!/usr/bin/perl
#
# test.pl for sFlow.pm
#
# Elisa Jasinska <elisa@ams-ix.net>
# 2006/07/20
#

use Test::More tests => 4;
use sFlow;

BEGIN { use_ok( 'sFlow' ); } 
require_ok( 'Math::BigInt' );
require_ok( 'Net::IP' );
require_ok( 'NetPacket' );
