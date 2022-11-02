# @TEST-EXEC: echo "===== Pre-compiled" >>output
# @TEST-EXEC: spicyz -o export.hlto export.spicy export.evt >>output
# @TEST-EXEC: ${ZEEK} export.hlto %INPUT >>output
# @TEST-EXEC: echo "===== JIT" >>output
# @TEST-EXEC: ${ZEEK} export.spicy export.evt %INPUT >>output
#
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test the `export` keyword to automatically create corresponding Zeek types.
#
# Note we run this both with and without precompilation to make sure that
# works. Internally, there are different code paths for the two cases.

module Test;

global u: Test::type_record_u = [$s="S", $b=T];
global s: Test::type_record_s = [$i=-10, $j=10, $$u=u];

event zeek_init() {
    local all = global_ids();
    for ( id in all ) {
	if ( ! (/Test::/ in id) )
	    next;

	if ( /type_record_/ in id )
            print id, record_fields(id);
	else
	    print id;
    }

    print "---";
    print s;
}

# @TEST-START-FILE export.spicy
module Test;

type type_record_s = struct {
    i: int32;
    j: uint8;
    u: type_record_u;
};

type type_record_u = unit {
    var s: string;
    var b: bool;
};

# @TEST-END-FILE

# @TEST-START-FILE export.evt

export Test::type_record_u;
export Test::type_record_s;

# @TEST-END-FILE
