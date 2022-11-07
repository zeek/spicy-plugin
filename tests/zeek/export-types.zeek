# @TEST-EXEC: echo "===== Pre-compiled" >>output
# @TEST-EXEC: spicyz -o export.hlto export.spicy export.evt >>output
# @TEST-EXEC: ${ZEEK} export.hlto %INPUT >>output
# @TEST-EXEC: echo "===== JIT" >>output
# @TEST-EXEC: ${ZEEK} export.spicy export.evt %INPUT >>output
#
# Zeek 5.0 doesn't include the ID when printing the enum type
# @TEST-EXEC: cat output | sed 's/enum Test::type_enum/enum/g' >output.tmp && mv output.tmp output
#
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test the `export` keyword to automatically create corresponding Zeek types.
#
# Note we run this both with and without precompilation to make sure that
# works. Internally, there are different code paths for the two cases.

module Test;

global e: Test::type_enum = Test::type_enum_B;
global u2: Test::type_record_u2 = [$t=[$x="S", $y=T]];
global u: Test::type_record_u = [$s="S", $b=T, $u2=u2];
global s: Test::type_record_s = [
    $a=1.2.3.4,
    $b="bytes",
    $e=e,
    $i=-10,
    $iv=5secs,
    $j=10,
    $m=table([4.3.2.1] = "addr1", [4.3.2.2] = "addr2"),
    $o="string",
    $p=42/tcp,
    $r=3.14,
    $s=set(Test::type_enum_A, Test::type_enum_B),
    $t=network_time(),
    $u=u,
    $v=vector("1", "2", "3")
];

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
	# else if ( /type_enum$/ in id )
	#     print id, enum_names(id); # Not available in 5.0 yet
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
    a: addr;
    b: bytes;
    e: type_enum;
    i: int32;
    iv: interval;
    j: uint8;
    m: map<addr, string>;
    o: optional<string>;
    p: port;
    r: real;
    s: set<type_enum>;
    t: time;
    u: type_record_u;
    v: vector<string>;
};

type type_record_u = unit {
    var s: string;
    var b: bool;
    var u2: type_record_u2;
};

type type_record_u2 = unit {
    var t: tuple<x: string, y: bool>;
};

# @TEST-END-FILE

# @TEST-START-FILE export.evt

export Test::type_enum;
export Test::type_record_u2;
export Test::type_record_u;
export Test::type_record_s;

# @TEST-END-FILE
