#!/usr/bin/perl
#
# Makefile.PL for sFlow.pm
#
# Elisa Jasinska <elisa@jasinska.de>
# 12/16/2014
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
