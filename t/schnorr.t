# -*-cperl-*-
#
# schnorr.t - Test script for Crypt::Schnorr::AuthSign
# Copyright (c) 2001 Ashish Gulhati <hash@netropolis.org>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: schnorr.t,v 1.1.1.1 2001/05/25 17:50:15 cvs Exp $

use strict;
use Test;

BEGIN { plan tests => 4 }

use Crypt::Schnorr::AuthSign;

ok(sub {
     my $schnorr = new Crypt::Schnorr::AuthSign;
     $schnorr->qsize(128);
     $schnorr->keygen('Name' => 'Test', Q => 500 );
     return 0 unless $schnorr->pubkey()->meta('Name') eq 'Test';
     return 0 if $schnorr->pubkey()->meta('Q') eq '500';
     1 
   }, 1);

ok(sub {
     my $schnorr = new Crypt::Schnorr::AuthSign;
     $schnorr->qsize(256);
     $schnorr->keygen('Name' => 'Another Test');
     return 0 unless my $k = Crypt::Schnorr::Key->new($schnorr->pubkey()->export());
     return 0 unless $k->meta('Name') eq 'Another Test';
     1 
   }, 1);

ok(sub {
     my $schnorr = new Crypt::Schnorr::AuthSign;
     $schnorr->qsize(512);
     $schnorr->keygen();
     my $sign = $schnorr->sign("This is a test\n");
     return 0 unless $schnorr->verify($sign, "This is a test\n");
     1 
   }, 1);

ok(sub {
     my $schnorr = new Crypt::Schnorr::AuthSign;
     $schnorr->qsize(1024);
     $schnorr->keygen();
     my $authreq = $schnorr->authreq();
     my $challenge = $schnorr->challenge($authreq);
     my $response = $schnorr->response($challenge);
     return 0 unless $schnorr->verify($response);
     1 
   }, 1);
