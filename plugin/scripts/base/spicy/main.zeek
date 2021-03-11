
@load base/misc/version

# doc-common-start
module Spicy;

export {
# doc-options-start
    ## Activate compile-time debugging output for given debug streams (comma-separated list).
    const codegen_debug = "" &redef;

    ## Enable debug mode for code generation.
    const debug = F &redef;

    ## If debug is true, add selected additional instrumentation (comma-separated list).
    const debug_addl = "" &redef;

    ## Save all generated code into files on disk.
    const dump_code = F &redef;

    ## Enable optimization for code generation.
    const optimize = F &redef;

    ## Report a break-down of compiler's execution time.
    const report_times = F &redef;

    ## Disable code valdidation.
    const skip_validation = F &redef;

    ## Show output of Spicy print statements.
    const enable_print = F &redef;

    ## abort() instead of throwing HILTI # exceptions.
    const abort_on_exceptions = F &redef;

    ## Include backtraces when reporting unhandled exceptions.
    const show_backtraces = F &redef;
# doc-options-end

# doc-functions-start
    ## Enable a specific Spicy protocol analyzer if not already active. If this
    ## analyzer replaces an standard analyzer, that one will automatically be
    ## disabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global enable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;

    ## Disable a specific Spicy protocol analyzer if not already inactive. If
    ## this analyzer replaces an standard analyzer, that one will automatically
    ## be re-enabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global disable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;


    # The following functions are only available with Zeek versions > 4.0.

@if ( Version::number >= 40100 )
    ## Enable a specific Spicy file analyzer if not already active. If this
    ## analyzer replaces an standard analyzer, that one will automatically be
    ## disabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global enable_file_analyzer: function(tag: Files::Tag) : bool;

    ## Disable a specific Spicy file analyzer if not already inactive. If
    ## this analyzer replaces an standard analyzer, that one will automatically
    ## be re-enabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global disable_file_analyzer: function(tag: Files::Tag) : bool;
@endif
# doc-functions-end
}

event spicy_analyzer_for_mime_type(a: Files::Tag, mt: string)
    {
    Files::register_for_mime_type(a, mt);
    }

function enable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }

@if ( Version::number >= 40100 )
function enable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }
@endif
