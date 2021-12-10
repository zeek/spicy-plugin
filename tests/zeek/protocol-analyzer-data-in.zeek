# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ssh-single-conn.trace ssh.spicy ./ssh-cond.evt %INPUT
# @TEST-EXEC: btest-diff http.log

# @TEST-START-FILE ssh.spicy
module SSH;

import spicy;
import zeek;

type Context = tuple<data_chunks: uint64>;

public type Banner = unit {
    %context = Context;
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};

on Banner::%done {
    zeek::protocol_begin("HTTP");
    zeek::protocol_data_in(True, b"GET /etc/passwd1 HTTP/1.0\r\n\r\n");
    zeek::protocol_data_in(False, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    zeek::protocol_end();

    zeek::protocol_begin(); # DPD
    zeek::protocol_data_in(True, b"GET /etc/passwd2 HTTP/1.0\r\n\r\n");
    zeek::protocol_data_in(False, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    zeek::protocol_end();
}
# @TEST-END-FILE

# @TEST-START-FILE ssh-cond.evt

import zeek;

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner,
    port 22/tcp,
    replaces SSH;

# @TEST-END-FILE
