#!/usr/bin/perl
#
# Makefile.PL for sFlow.pm
#
# Elisa Jasinska <elisa.jasinska@ams-ix.net>
# 2008/12/8
#


use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'            => 'Net::sFlow',
    'VERSION_FROM'    => 'sFlow.pm', # finds $VERSION
    'LIBS'            => ['-lm'], # e.g., '-lm'
    'EXE_FILES'       =>  [ 'examples/sFluxDebug.pl'],
    'INSTALLSCRIPT'   => "/usr/local/bin",
    'ABSTRACT'        => 'decode sFlow datagrams',
    'AUTHOR'          => 'Elisa Jasinska <elisa.jasinska@ams-ix.net>',
    'dist'            => { COMPRESS  =>  'gzip',
                           SUFFIX    =>  'gz'
                         },
);
