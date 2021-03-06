#!/usr/bin/perl
#	$OpenBSD: relay.pl,v 1.3 2014/08/18 22:58:19 bluhm Exp $

# Copyright (c) 2010-2014 Alexander Bluhm <bluhm@openbsd.org>
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
use Socket;
use Socket6;

use Client;
use Relay;
use Server;
require 'funcs.pl';

sub usage {
	die "usage: relay.pl copy|splice [args-test.pl]\n";
}

my $testfile;
our %args;
if (@ARGV and -f $ARGV[-1]) {
	$testfile = pop;
	do $testfile
	    or die "Do test file $testfile failed: ", $@ || $!;
}
@ARGV == 1 or usage();

my $s = Server->new(
    idle		=> 4,
    func		=> \&read_datagram,
    listendomain	=> AF_INET,
    listenaddr		=> "127.0.0.1",
    %{$args{server}},
    protocol            => "udp",
);
my $r = Relay->new(
    forward		=> $ARGV[0],
    idle		=> 3,
    func		=> \&relay,
    listendomain	=> AF_INET,
    listenaddr		=> "127.0.0.1",
    connectdomain	=> AF_INET,
    connectaddr		=> "127.0.0.1",
    connectport		=> $s->{listenport},
    %{$args{relay}},
    protocol            => "udp",
);
my $c = Client->new(
    func		=> \&write_datagram,
    connectdomain	=> AF_INET,
    connectaddr		=> "127.0.0.1",
    connectport		=> $r->{listenport},
    %{$args{client}},
    protocol            => "udp",
);

$s->run;
$r->run;
$c->run->up;
$r->up;
$s->up;

$c->down;
$r->down;
$s->down;

check_logs($c, $r, $s, %args);
