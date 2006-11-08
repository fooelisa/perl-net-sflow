#!/usr/bin/perl
#
# test.pl for sFlow.pm
#
# Elisa Jasinska <elisa.jasinska@ams-ix.net>
# 2006/11/8
#

use Test::More qw(no_plan);
use Test::Pod;

BEGIN { use_ok( 'Net::sFlow' ); } 
BEGIN { use_ok( 'Math::BigInt' ); }
BEGIN { use_ok( 'Test::Pod' ); }

pod_file_ok( 'blib/lib/Net/sFlow.pm', "Valid POD file" );
