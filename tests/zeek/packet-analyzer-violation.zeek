# @TEST-DOC: Checks that packet analyzers correctly report violations. This is a regression test for #132.

# @TEST-EXEC: spicyz -d -o zeek_test.hlto analyzer.spicy analyzer.evt
# @TEST-EXEC: HILTI_DEBUG=spicy ${ZEEK} -Cr ${TRACES}/packet-analyzer-violation.pcap zeek_test.hlto %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE analyzer.spicy
module test;
public type Foo = unit {
  data: bytes &until=b"\xbe";
};
# @TEST-END-FILE

# @TEST-START-FILE analyzer.evt
import test;

packet analyzer spicy::TEST:
    parse with test::Foo;
# @TEST-END-FILE

module TEST;

event zeek_init()
{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x6666,
	    "spicy_TEST") )
		print "cannot register spicy analyzer";
}
