@load Zeek/Spicy/bare.zeek

# `bare_mode` only appeared with zeek-5.
@ifdef ( bare_mode )
@if ( ! bare_mode() )
@load Zeek/Spicy/default.zeek
@endif

# Always emit logs as a fallback for older Zeek versions.
@else
@load Zeek/Spicy/default.zeek

@endif
