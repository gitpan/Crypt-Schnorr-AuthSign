# -*-cperl-*-
#
# Crypt::Schnorr::AuthSign - Schnorr Authentication & Signature Protocols
# Copyright (c) 2001 Ashish Gulhati <hash@netropolis.org>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: AuthSign.pm,v 1.10 2001/05/26 15:54:53 cvs Exp $

use strict;

package Crypt::Schnorr::Key;

sub new {
  my $class = shift; 
  my $key = Crypt::Schnorr::AuthSign->__grokpacket(shift);
  bless $key, $class;
}

sub export {
  my $self = shift;
  Crypt::Schnorr::AuthSign->__packetize($self);
}

sub meta {
  my $self = shift; 
  return map { $_ => $self->{$_} } grep { !/^P|Q|G|H|X|TYPE$/ } keys %$self
    unless my $metalabel = shift;
  unless ($metalabel =~ m/^P|Q|G|H|X|TYPE$/) {
    $self->{$metalabel} = shift if (defined $_[0]);
  }
  return $self->{$metalabel};
}

package Crypt::Schnorr::AuthSign;

use Safe;
use MIME::Base64;
use Data::Dumper;
use Compress::Zlib;
use Crypt::Primes qw(maurer);
use Digest::SHA1 qw(sha1_hex);
use vars qw( $VERSION $AUTOLOAD );
use Crypt::Random qw(makerandom makerandom_itv);
use Math::Pari qw(PARI Mod component random truncate floor round divisors);

( $VERSION ) = '$Revision: 1.10 $' =~ /\s+([\d\.]+)/;

sub new {
  bless { VERSION        =>   "Crypt::Schnorr::AuthSign v$VERSION",
	  COMMENT        =>   '',
	  DEBUG          =>   1,
	  QSIZE          =>   1024,
	  HASH           =>   sub { "0x" . sha1_hex($_[0]) }
	}, shift;
}

sub keygen {
  my $self = shift; my %meta = @_; my $x; my $p;
  %meta = map { $_, $meta{$_} } grep { $_ !~ m/^P|Q|G|H|X|TYPE$/ } keys %meta;
  my $q = maurer ( Size => $self->{QSIZE}, Verbosity => $self->{DEBUG}, 
		   Intermediates => 1, Generator => 1, Factors => 1 );
  for (sort { $a <=> $b } (@{$q->{Factors}}, $q->{Intermediates}->[$#{$q->{Intermediates}}])) {
    $p = $_, last if $_ > 65537 and $_ > 2**($self->{QSIZE}/3);
  }
  $p = $q->{Intermediates}->[$#{$q->{Intermediates}}] unless $p;
  my $Q = $q->{Prime};
  my @divisors = divisors($q->{R}) =~ m:[\[\(\;\,](\d+):g;

  # Find a generator of G(p) in Z(q). 
  my $g;
  while ($x = Mod(makerandom_itv( Lower => 2, Upper => $Q-1), $Q)) {
    print "." if $self->{DEBUG};
    $g = $x, last if $x ** $p == 1; 
    for (@divisors[1..$#divisors]) {
      my $y = $x ** $_; $g = $y, last if $y != 1 and $y ** $p == 1;
    }
    last if $g;
  }

  $x = makerandom_itv( Lower => 1, Upper => $p, Strength => 0 );
  my $h = component($g**$x,2); $g = component($g,2);
  print "\nq: $Q\np: $p\ng: $g\nh: $h\nx: $x\n" if $self->{DEBUG}; 

  $self->{PUBKEY} = bless { VERSION => $self->{VERSION}, COMMENT => $self->{COMMENT},
			    TYPE => 'PUBLIC KEY BLOCK', P => "$p", Q => "$Q", G => "$g",
			    H => "$h", %meta }, 'Crypt::Schnorr::Key';
  $self->{SECRETKEY} = bless { %{$self->{PUBKEY}}, TYPE => 'SECRET KEY BLOCK', 
			       X => "$x" }, 'Crypt::Schnorr::Key';
}

sub authreq {
  my $self = shift; 
  $self->{W} = makerandom_itv( Lower => 1, Upper => $self->{SECRETKEY}->{P}, Strength => 0 );
  $self->{A} = component(Mod($self->{SECRETKEY}->{G},$self->{SECRETKEY}->{Q}) ** $self->{W},2);
  print "w: $self->{W}\na: $self->{A}\n" if $self->{DEBUG}; 
  $self->__packetize({ TYPE => 'AUTH REQUEST', A => "$self->{A}"});
}

sub challenge {
  my $self = shift; my $packet = $self->__grokpacket(shift); $self->{A} = $packet->{A}; 
  $self->{C} = makerandom_itv( Lower => 0, Upper => Math::Pari->new('2^72-1'), Strength => 0 );
  print "c: $self->{C}\n" if $self->{DEBUG};
  $self->__packetize({ TYPE => 'AUTH CHALLENGE', C => "$self->{C}"});
}

sub response {
  my $self = shift; my $packet = $self->__grokpacket(shift); $self->{C} = $packet->{C};
  $self->{R} = component(Mod($self->{SECRETKEY}->{X},$self->{SECRETKEY}->{P})*$self->{C}+$self->{W},2);
  print "r: $self->{R}\n" if $self->{DEBUG};
  $self->__packetize({ TYPE => 'AUTH RESPONSE', R => "$self->{R}"});
}

sub verify {
  my $self = shift; my $packet = $self->__grokpacket(shift); $self->{R} = $packet->{R};
  if ($packet->{TYPE} eq 'SIGNATURE') {
    $self->{C} = $packet->{C}; $self->{A} = $packet->{A};
  }
  my $a = Mod($self->{PUBKEY}->{G},$self->{PUBKEY}->{Q})**$self->{R};
  my $b = (Mod($self->{PUBKEY}->{H},$self->{PUBKEY}->{Q})**$self->{C})*$self->{A};
  print "g ^ r    mod q = ", $a, "\n" if $self->{DEBUG};
  print "a * h ^c mod q = ", $b, "\n" if $self->{DEBUG};
  my $valid = $a == $b;
  if ($valid and $packet->{TYPE} eq 'SIGNATURE') {
    my $m = shift; 
    my $c = &{$self->{HASH}}($m . $self->{A});
    $valid = $c eq $self->{C};
  }
  $valid;
}

sub sign {
  my $self = shift; my $message = shift; 
  $self->authreq(); my $hash = $self->{HASH};
  $self->{C} = &$hash($message . $self->{A});
  $self->response($self->__packetize({ TYPE => 'AUTH CHALLENGE', C => "$self->{C}"})); 
  $self->__packetize({ TYPE => 'SIGNATURE', C => "$self->{C}", R => "$self->{R}", A => "$self->{A}" });
}

sub __packetize {
  my $s = shift; undef $s unless ref $s; my $object = shift; my ($version, $comment) = ('','');
  my $dump = defined &Data::Dumper::Dumpxs ?
    Data::Dumper::DumperX($object) : Data::Dumper::Dumper($object);
  my $packet = encode_base64(compress($dump),''); $packet =~ s/(.{64})/$1\n/sg; 
  $packet =~ s/\n$//sg; $packet =~ s/([^\n]{64})\n$/$1/sg;
  if ($s) {
    $version = "Version: $s->{VERSION}\n" if $s->{VERSION};
    $comment = "Comment: $s->{COMMENT}\n" if $s->{COMMENT};  
  }
  else {
    $version = "Version: $object->{VERSION}\n" if $object->{VERSION};
    $comment = "Comment: $object->{COMMENT}\n" if $object->{COMMENT};
  }
  return <<__ENDPACKET;
-----BEGIN SCHNORR $object->{TYPE}-----
$version$comment
$packet
-----END SCHNORR $object->{TYPE}-----
__ENDPACKET
}

sub __grokpacket {
  shift; my $packet = shift =~ /\n\n(.*)-----END SCHNORR/sg; $packet = $1;
  my $box = new Safe; $box->permit_only(qw(bless anonhash refgen :base_core));
  $box->reval(uncompress(decode_base64($packet))); 
}

sub AUTOLOAD {
  my $self = shift; (my $auto = $AUTOLOAD) =~ s/.*:://;
  return if $auto eq 'DESTROY';
  if ($auto =~ /^((secret|pub)key|qsize|debug|version|comment|hash)$/x) {
    $self->{"\U$auto"} = shift if (defined $_[0]);
    return $self->{"\U$auto"};
  }
  else {
    die "Could not AUTOLOAD method $auto.";
  }
}

"True Value";

__END__

=head1 NAME 

Crypt::Schnorr::AuthSign - Schnorr Authentication & Signature Protocols

=head1 VERSION

 $Revision: 1.10 $
 $Date: 2001/05/26 15:54:53 $

=head1 SYNOPSIS

  use Crypt::Schnorr::AuthSign;

  $schnorr = new Crypt::Schnorr::AuthSign;

  $schnorr->qsize(512);                   # Use a 512 bit modulus.

  $schnorr->keygen(Name => 'Test User');  # Create a new keypair.

  $req = $schnorr->authreq();             # Create auth request.
  $c = $schnorr->challenge($req);         # Generate auth challenge.
  $response = $schnorr->response($c);     # Respond to a challenge.
  $auth = $schnorr->verify($response);    # Verify auth response.

  $sign = $schnorr->sign($m);             # Create a signature for $m.
  $valid = $schnorr->verify($sign, $m);   # Verify signature on $m.

=head1 DESCRIPTION

This module implements the basic Schnorr authentication and signature
protocols. It supports zlib compression, Radix64 encoding for exported
keys and protocol packets, and a simple method for binding metadata to
keys. It does not provide any key management functions or maintain a
key database.

=head1 CONSTRUCTOR

=over 2

=item B<new()>

Creates and returns a new Crypt::Schnorr::AuthSign object.

=back

=head1 DATA METHODS

=over 2

=item B<qsize()>

Sets the B<QSIZE> instance variable which can be used to change the
bitlength of the prime 'q' which is the modulus for most of the
calculations in the protocol. A smaller prime, 'p' (q=pk+1) is also
used - its bitlength is dependent on the choice of q.

=item B<secretkey()>

If called without parameters, returns the Crypt::Schnorr::Key object
corresponding to the active secret key. If passed a
Crypt::Schnorr::Key object, makes that key the currently active secret
key.

=item B<pubkey()>

If called without parameters, returns the Crypt::Schnorr::Key object
corresponding to the active public key. If passed a
Crypt::Schnorr::Key object, makes that key the currently active public
key.

=item B<version()>

Sets the B<VERSION> instance variable which can be used to change the
Version: string on the generated protocol packets to whatever you
like. If called without parameters, simply returns the value of the
B<VERSION> instance variable.

=item B<comment()>

Sets the B<COMMENT> instance variable which can be used to change the
Comment: string on the generated protocol packets to whatever you
like. If called without parameters, simply returns the value of the
B<COMMENT> instance variable.

=item B<debug()>

Sets the B<DEBUG> instance variable which causes the module to emit
debugging information if set to a true value. If called without
parameters, simply returns the value of the B<DEBUG> instance
variable.

=item B<hash()>

Sets or fetches the B<HASH> instance variable - a coderef. The
referenced routine should compute a message digest of it's first
argument and return the digest as a decimal or hex number.

=back

=head1 OBJECT METHODS

=over 2

=item B<keygen(%metainfo)>

Generates new public key parameters, creates a new keypair, and binds
the name/value pairs of %metainfo with it. Sets the active secret and
public keys to the generated keypair. Returns undef if there was an
error, otherwise returns a filehandle that reports the progress of the
key generation process.

=item B<authreq()>

Creates and returns an authorization request. Saves parameters
associated with the request for use in the rest of the authorization
protocol.

=item B<challenge($authreq)>

Generates and returns a challenge to the authorization request in
$authreq, and saves the request parameters for use in the rest of the
authorization protocol.

=item B<response($challenge)>

Generates and returns a response to the authorization challenge in
$challenge, using some of the information saved by the last call to
B<authreq()>.

=item B<sign($message)>

Computes a message digest of $message, and returns a signature on this
message digest. The message digest is computed using the default hash
routine (SHA1 with Digest::SHA1) or the hash routine set with the last
call to B<hash()>.

=item B<verify($response)>

Attempts to verify the response packet $response against the currently
active public key, which should previously have been set by a call to
B<pubkey()> or some other method. Returns true iff the authorization
succeeded.

=back

=head1 KEY OBJECT METHODS

=over 2

=item B<new($keypacket)>

Creates a new Crypt::Schnorr::Key object and initializes it from the
key information in $keypacket. The $keypacket argument is required.

=item B<export()>

Returns a Radix64 encoded representation of the key.

=item B<meta()>

Allows metadata access. Provide a label to retrieve the value
associated with it, provide a label/value pair and it will be
associated with the key, replacing the old value if metadata with the
specified label already exists. If called without parameters, will
return a list containing all metadata key/value pairs.

=back

=head1 AUTHOR

Crypt::Schnorr::AuthSign is Copyright (c) 2001 Ashish Gulhati
<hash@netropolis.org>. All Rights Reserved.

=head1 LICENSE

This code is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 DISCLAIMER

This is free software. If it breaks, you own both parts.

=cut
