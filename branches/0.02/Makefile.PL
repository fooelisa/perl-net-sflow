#!/usr/bin/perl
#
# Makefile.PL for sFlow.pm
#
# Elisa Jasinska <elisa.jasinska@ams-ix.net>
# 2006/07/27
#


use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'            => 'Net::sFlow',
    'VERSION_FROM'    => 'lib/Net/sFlow.pm', # finds $VERSION
    'LIBS'    => ['-lm'], # e.g., '-lm'
    'dist'            => {
        COMPRESS  =>  'gzip',
        SUFFIX    =>  'gz'
    },
);
