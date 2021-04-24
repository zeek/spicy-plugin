# @TEST-EXEC: ${ZEEK} -r ${TRACES}/http-post.trace text.spicy ./text.evt %INPUT Spicy::enable_print=T >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff files.log

event text::data3(f: fa_file, data: string)
	{
	print "data3", f$id, data;
	}

# @TEST-START-FILE text.spicy
module Text;

import zeek;

public type Data1 = unit {
    data: bytes &eod {
        zeek::file_begin("text/plain2");
        zeek::file_data_in(b"from 1:" + self.data);
        zeek::file_end();
    }
};

public type Data2 = unit {
    data: bytes &eod {
        zeek::file_begin("text/plain3");
        zeek::file_data_in(b"from 2a:" + self.data);
        zeek::file_end();

        zeek::file_begin("text/plain3");
        zeek::file_data_in(b"from 2b:" + self.data);
        zeek::file_end();
    }
};

public type Data3 = unit {
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE text.evt

file analyzer spicy::Text1:
    parse with Text::Data1,
    mime-type text/plain;

file analyzer spicy::Text2:
    parse with Text::Data2,
    mime-type text/plain2;

file analyzer spicy::Text3:
    parse with Text::Data3,
    mime-type text/plain3;

on Text::Data3 -> event text::data3($file, self.data);
# @TEST-END-FILE
