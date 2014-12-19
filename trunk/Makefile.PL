#!/usr/bin/perl
#
# Makefile.PL for sFlow.pm
#
# Elisa Jasinska <elisa@jasinska.de>
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

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'            => 'Net::sFlow',
    'VERSION_FROM'    => 'sFlow.pm', # finds $VERSION
    'LIBS'            => ['-lm'], # e.g., '-lm'
    'ABSTRACT'        => 'decode sFlow datagrams',
    'EXE_FILES'       =>  [ 'examples/sFluxDebug.pl'],
    'INSTALLSCRIPT'   => "/usr/local/bin",
    'AUTHOR'          => 'Elisa Jasinska <elisa@jasinska.de>',
    'dist'            => { COMPRESS  =>  'gzip',
                           SUFFIX    =>  'gz'
                         },
);
