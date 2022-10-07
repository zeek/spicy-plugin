# @TEST-EXEC: ${ZEEK} -r ${TRACES}/raw-layer.pcap raw-layer.spicy raw-layer.evt %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff conn.log
# @TEST-EXEC: btest-diff weird.log

module PacketAnalyzer::SPICY_RAWLAYER;

event zeek_init()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88b5, PacketAnalyzer::ANALYZER_SPICY__RAWLAYER);

	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("spicy::RawLayer", 0x4950, "IP") )
		print "cannot register IP analyzer";
	}

event raw::data(p: raw_pkt_hdr, data: string)
	{
	print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	print "raw data", data;
	}

# @TEST-START-FILE raw-layer.spicy
module RawLayer;

import zeek;

public type Packet = unit {
    data: bytes &size=19;
    protocol: uint16;

    on %done {
        zeek::forward_packet(self.protocol);
        zeek::weird("test_weird");
    }
};
# @TEST-END-FILE

# @TEST-START-FILE raw-layer.evt
packet analyzer spicy::RawLayer:
    parse with RawLayer::Packet;

on RawLayer::Packet::data -> event raw::data($packet, self.data);
# @TEST-END-FILE
