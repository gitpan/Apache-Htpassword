# $Id: test.pl,v 0.3 1998/10/22 02:49:53 meltzek Exp $
# $Log: test.pl,v $
# Revision 0.3  1998/10/22 02:49:53  meltzek
# Added verbose begining and ending of test.
#
# Revision 0.2  1998/10/22 02:46:56  meltzek
# Added new checks.
#

BEGIN { $| = 1; print "Tests 1..8 begining\n"; }
END {print "not ok 1\n" unless $loaded;}
use Apache::Htpasswd;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

sub report_result {
	my $ok = shift;
	$TEST_NUM ||= 2;
	print "not " unless $ok;
	print "ok $TEST_NUM\n";
	print "@_\n" if (not $ok and $ENV{TEST_VERBOSE});
	$TEST_NUM++;
}

# Create a test password file
my $File = "testpasswords.test";
open(TEST,">$File");
print TEST "kevin:kjDqW.pgNIz3Ufoo:suvPq./X7Q8nk\n";
close TEST;



{
	
	# 2: open a database
	&report_result($pwdFile = new Apache::Htpasswd ($File), $! );

	# 3: store a value
	&report_result($pwdFile->htpasswd("foo","foobar") , $! );

	# 4: store a new hash 
	&report_result($pwdFile->htpasswd("foo", "goo","foobar" ) , $! );
	
	# 5: retie the hash
	&report_result($pwdFile->htpasswd("foo","ummm",1), $! );

	# 6: check the stored value
	&report_result($pwdFile->fetchPass("foo") , $!);

	# 7: check whether the empty key exists()
	&report_result($pwdFile->htCheckPassword("foo","ummm"),$!);

	# 8: check whether the empty key exists()
	&report_result($pwdFile->htDelete("kevin"),$!);
	
}

print "Test complete.\n";
