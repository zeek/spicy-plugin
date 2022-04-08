# @TEST-EXEC: HILTI_DEBUG=zeek ${ZEEK} -r ${TRACES}/ssh-single-conn.trace misc/dump-events test.evt test.spicy %INPUT
# @TEST-EXEC: btest-diff dpd.log
#
# @TEST-DOC: Trigger parse error after confirmation, should be recorded in dpd.log

# @TEST-START-FILE test.spicy
module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/ { zeek::confirm_protocol(); }
    version : /[^-]*/;
    dash    : /-/;
    software: /KAPUTT/;
};
# @TEST-END-FILE

# @TEST-START-FILE test.evt

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner,
    port 22/tcp

    # With Zeek < 5.0, DPD tracking doesn't work correctly for replaced
    # analyzers because the ProtocolViolation() doesn't take a tag.
    #
    # replaces SSH
    ;

# @TEST-END-FILE
