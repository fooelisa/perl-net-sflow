#!/usr/bin/perl
#
# Makefile.PL for sFlow.pm
#
# Elisa Jasinska <elisa@ams-ix.net>
# 2006/07/20
#


use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'            => 'sFlow',
    'VERSION_FROM'    => 'sFlow.pm', # finds $VERSION
    'LIBS'    => ['-lm'], # e.g., '-lm'
    'INSTALLMAN3DIR'  => 'none',
    'dist'            => {
        COMPRESS  =>  'gzip',
        SUFFIX    =>  'gz'
    },
);
