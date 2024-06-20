#!/usr/bin/perl
#
# test.pl for sFlow.pm
#
# Elisa Jasinska <elisa@bigwaveit.org>
# 12/19/2014
#
#
# Copyright (c) 2006 - 2015 AMS-IX B.V.
#
# This package is free software and is provided "as is" without express
# or implied warranty.  It may be used, redistributed and/or modified
# under the terms of the Perl Artistic License (see
# http://www.perl.com/perl/misc/Artistic.html)
#

use Test::More qw(no_plan);

BEGIN { use_ok( 'Net::sFlow' ); } 
BEGIN { use_ok( 'Math::BigInt' ); }
