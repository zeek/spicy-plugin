# @TEST-EXEC: spicyz -o ssh.hlto ssh.spicy ./ssh.evt
# @TEST-EXEC: echo === confirmation >>output
# @TEST-EXEC: ${ZEEK} -b -r ${TRACES}/ssh-single-conn.trace -s ./ssh.sig Zeek::Spicy ssh.hlto %INPUT ./extern.zeek | sort >>output
# @TEST-EXEC: echo === violation >>output
# @TEST-EXEC: ${ZEEK} -b -r ${TRACES}/http-post.trace -s ./ssh.sig Zeek::Spicy ssh.hlto  ./extern.zeek %INPUT | sort >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

event ssh::banner(c: connection, is_orig: bool, version: string, software: string)
	{
	print "SSH banner", c$id, is_orig, version, software;
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
	{
    if ( atype == Analyzer::ANALYZER_SPICY_SSH )
	    print "confirm", atype;
	}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string)
	{
    if ( atype == Analyzer::ANALYZER_SPICY_SSH )
	    print "violation", atype;
	}

# @TEST-START-FILE extern.zeek

module Foo;

event ssh::banner(c: connection, is_orig: bool, version: string, software: string)
	{
	print "SSH banner in Foo", c$id, is_orig, version, software;
	}
# @TEST-END-FILE

# @TEST-START-FILE ssh.spicy
module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;

    on %done { zeek::confirm_protocol(); assert zeek::uid() == "CHhAvVGS1DHFjwGM9"; }
    on %error { zeek::reject_protocol("kaputt"); }
};
# @TEST-END-FILE

# @TEST-START-FILE ssh.sig

signature ssh_server {
    ip-proto == tcp
    payload /./
    enable "spicy_SSH"
    tcp-state responder
}
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    # no port, we're using the signature
    parse with SSH::Banner;

on SSH::Banner -> event ssh::banner($conn, $is_orig, self.version, self.software);
# @TEST-END-FILE
