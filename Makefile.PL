use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile (
	       'NAME'	      =>   'Crypt::Schnorr::AuthSign',
	       'AUTHOR'        =>  'Ashish Gulhati <hash@netropolis.org>',
	       'ABSTRACT_FROM' =>  'AuthSign.pm',
	       'VERSION_FROM'  =>  'AuthSign.pm',
	       'PREREQ_PM'     =>  {
				    Safe => 0,
				    MIME::Base64 => 0,
				    Data::Dumper => 0,
				    Compress::Zlib => 0,
				    Crypt::Primes => 0.47,
				    Digest::SHA1 => 0,
				   },
	      );

