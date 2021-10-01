# $OpenBSD: Program.pm,v 1.18 2012/07/12 19:21:00 espie Exp $

# Copyright (c) 2007-2010 Steven Mestdagh <steven@openbsd.org>
# Copyright (c) 2012 Marc Espie <espie@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings;
use feature qw(say switch state);

package LT::Program;
use File::Basename;
use LT::Archive;
use LT::Util;
use LT::Trace;

sub new
{
	my $class = shift;
	bless {}, $class;
}

# write a wrapper script for an executable so it can be executed within
# the build directory
sub write_wrapper
{
	my $self = shift;

	my $program = $self->{outfilepath};
	my $pfile = basename($program);
	my $realprogram = $ltdir . '/' . $pfile;
	open(my $pw, '>', $program) or die "Cannot write $program: $!\n";
	print $pw <<EOF
#!/bin/sh

# $program - wrapper for $realprogram
# Generated by libtool $version

argdir=`dirname \$0`
if test -f "\$argdir/$realprogram"; then
    # Add our own library path to LD_LIBRARY_PATH
    LD_LIBRARY_PATH=\$argdir/$ltdir
    export LD_LIBRARY_PATH

    # Run the actual program with our arguments.
    exec "\$argdir/$realprogram" \${1+"\$\@"}

    echo "\$0: cannot exec $program \${1+"\$\@"}"
    exit 1
else
    echo "\$0: error: \\\`\$argdir/$realprogram' does not exist." 1>&2
    exit 1
fi
EOF
;
	close($pw);
	chmod 0755, $program;
}

sub install
{
	my ($class, $src, $dst, $instprog, $instopts) = @_;

	my $srcdir = dirname $src;
	my $srcfile = basename $src;
	my $realpath = "$srcdir/$ltdir/$srcfile";
	LT::Exec->install(@$instprog, @$instopts, $realpath, $dst);
}

1;
