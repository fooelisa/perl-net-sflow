#!/usr/bin/perl
#
# Makefile.PL for sFlow.pm
#
# Elisa Jasinska <elisa.jasinska@ams-ix.net>
# 2006/11/25
#


use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'            => 'Net::sFlow',
    'VERSION_FROM'    => 'sFlow.pm', # finds $VERSION
    'LIBS'            => ['-lm'], # e.g., '-lm'
    'ABSTRACT'        => 'decode sFlow datagrams',
    'AUTHOR'          => 'Elisa Jasinska <elisa.jasinska@ams-ix.net>',
    'dist'            => { COMPRESS  =>  'gzip',
                           SUFFIX    =>  'gz'
                         },
);
