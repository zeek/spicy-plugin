# @TEST-EXEC: ${ZEEK} -r ${TRACES}/dns53-proto-255.pcap raw-layer.spicy raw-layer.evt %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff output

module PacketAnalyzer::SPICY_RAWLAYER;

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 255, "spicy::RawLayer") ) # modified trace to have IP proto 255
		print "cannot register raw analyzer on top of IP";
	}

event raw::data(p: raw_pkt_hdr, data: string)
	{
    print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
    print fmt("IPs : src=%s dst=%s", p$ip$src, p$ip$dst);
	print fmt("raw bytes: %d", |data|);
	}

# @TEST-START-FILE raw-layer.spicy
module RawLayer;

import zeek;

public type Packet = unit {
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE raw-layer.evt
packet analyzer spicy::RawLayer:
    parse with RawLayer::Packet;

on RawLayer::Packet::data -> event raw::data($packet, self.data);
# @TEST-END-FILE
