// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/file-analyzer.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-reporter.h>

#include "consts.bif.h"
#include "events.bif.h"

using namespace spicy::zeek;
using namespace spicy::zeek::rt;
using namespace plugin::Zeek_Spicy;

#ifndef NDEBUG
#define STATE_DEBUG_MSG(...) DebugMsg(__VA_ARGS__)
#else
#define STATE_DEBUG_MSG(...)
#endif

void FileState::debug(const std::string& msg) { spicy::zeek::rt::debug(_cookie, msg); }

static auto create_file_state(FileAnalyzer* analyzer) {
    uint64_t depth = 0;
    if ( auto current_cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( const auto f = std::get_if<cookie::FileAnalyzer>(current_cookie) )
            depth = f->depth + 1;
    }

    cookie::FileAnalyzer cookie{.analyzer = analyzer,
                                .depth = depth,
                                .fstate = cookie::FileStateStack(analyzer->GetFile()->GetID())};
    return FileState(cookie);
}

FileAnalyzer::FileAnalyzer(::zeek::RecordValPtr args, ::zeek::file_analysis::File* file)
    : ::zeek::file_analysis::Analyzer(std::move(args), file), _state(create_file_state(this)) {}

FileAnalyzer::~FileAnalyzer() {}

void FileAnalyzer::Init() {}

void FileAnalyzer::Done() {}

bool FileAnalyzer::DeliverStream(const u_char* data, uint64_t len) {
    ::zeek::file_analysis::Analyzer::DeliverStream(data, len);

    return Process(len, data);
}

bool FileAnalyzer::Undelivered(uint64_t offset, uint64_t len) {
    ::zeek::file_analysis::Analyzer::Undelivered(offset, len);

    STATE_DEBUG_MSG("undelivered data, skipping further originator payload");
    _state.skipRemaining();
    return false;
}

bool FileAnalyzer::EndOfFile() {
    ::zeek::file_analysis::Analyzer::EndOfFile();
    Finish();
    return false;
}

bool FileAnalyzer::Process(int len, const u_char* data) {
    if ( ! _state.hasParser() && ! _state.isSkipping() ) {
        auto parser = OurPlugin->parserForFileAnalyzer(_state.cookie().analyzer->Tag());
        ;
        if ( parser )
            _state.setParser(parser);
        else {
            STATE_DEBUG_MSG("no unit specified for parsing");
            _state.skipRemaining();
            return false;
        }
    }

    auto* file = _state.cookie().analyzer->GetFile();

    const auto& max_file_depth = ::zeek::BifConst::Spicy::max_file_depth;

    if ( _state.cookie().depth >= max_file_depth ) {
        const auto& file_val = file->ToVal();

        const auto analyzer_args = _state.cookie().analyzer->GetArgs();

        file->FileEvent(Spicy::max_file_depth_exceeded,
                        {file_val, analyzer_args, ::zeek::val_mgr->Count(_state.cookie().depth)});
        reporter::analyzerError(_state.cookie().analyzer, "maximal file depth exceeded", "Spicy file analysis plugin");
        return false;
    }

    try {
        hilti::rt::context::CookieSetter _(&_state.cookie());
        _state.process(len, reinterpret_cast<const char*>(data));
    } catch ( const spicy::rt::ParseError& e ) {
        reporter::weird(file, e.what());
    } catch ( const hilti::rt::Exception& e ) {
        STATE_DEBUG_MSG(e.what());
        reporter::analyzerError(_state.cookie().analyzer, e.description(),
                                e.location()); // this sets Zeek to skip sending any further input
    }

    return true;
}

void FileAnalyzer::Finish() {
    try {
        hilti::rt::context::CookieSetter _(&_state.cookie());
        _state.finish();
    } catch ( const spicy::rt::ParseError& e ) {
        reporter::weird(_state.cookie().analyzer->GetFile(), e.what());
    } catch ( const hilti::rt::Exception& e ) {
        reporter::analyzerError(_state.cookie().analyzer, e.description(),
                                e.location()); // this sets Zeek to skip sending any further input
    }
}

::zeek::file_analysis::Analyzer* FileAnalyzer::InstantiateAnalyzer(::zeek::RecordValPtr args,
                                                                   ::zeek::file_analysis::File* file) {
    return new FileAnalyzer(std::move(args), file);
}
