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

global e: Test::type_enum = Test::type_enum_B;
global u: Test::type_record_u = [$s="S", $b=T];
global s: Test::type_record_s = [$i=-10, $j=10, $u=u, $e=e];

event zeek_init() {
    local all_globals: vector of string;
    for ( id in global_ids() )
	all_globals[|all_globals|] = id;

    sort(all_globals, strcmp);

    for ( i in all_globals ) {
	id = all_globals[i];

	if ( ! (/Test::/ in id) )
	    next;

	if ( /type_record_/ in id )
            print id, record_fields(id);
	else if ( /type_enum$/ in id )
	    print id, enum_names(id);
	else
	    print id;
    }

    print "---";
    print s;
}

# @TEST-START-FILE export.spicy
module Test;

type type_enum = enum { A, B, C };

type type_record_s = struct {
    i: int32;
    j: uint8;
    u: type_record_u;
    e: type_enum;
};

type type_record_u = unit {
    var s: string;
    var b: bool;
};

# @TEST-END-FILE

# @TEST-START-FILE export.evt

export Test::type_enum;
export Test::type_record_u;
export Test::type_record_s;

# @TEST-END-FILE
