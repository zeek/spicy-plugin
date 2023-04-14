// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/plugin/packet-analyzer.h>
#include <zeek-spicy/plugin/plugin.h>
#include <zeek-spicy/plugin/runtime-support.h>
#include <zeek-spicy/plugin/zeek-reporter.h>

#ifndef NDEBUG
#define STATE_DEBUG_MSG(...) DebugMsg(__VA_ARGS__)
#else
#define STATE_DEBUG_MSG(...)
#endif

using namespace spicy::zeek;
using namespace spicy::zeek::rt;
using namespace plugin::Zeek_Spicy;

void PacketState::debug(const std::string& msg) { spicy::zeek::rt::debug(_cookie, msg); }

static auto create_packet_state(PacketAnalyzer* analyzer) {
    cookie::PacketAnalyzer cookie;
    cookie.analyzer = analyzer;
    return PacketState(std::move(cookie));
}

PacketAnalyzer::PacketAnalyzer(std::string name)
    : ::zeek::packet_analysis::Analyzer(std::move(name)), _state(create_packet_state(this)) {}

PacketAnalyzer::~PacketAnalyzer() = default;

bool PacketAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, ::zeek::Packet* packet) {
    if ( auto parser = OurPlugin->parserForPacketAnalyzer(_state.packet().analyzer->GetAnalyzerTag()) )
        _state.setParser(parser);
    else
        reporter::fatalError("no valid unit specified for parsing");

    try {
        hilti::rt::context::CookieSetter _(_state.cookie());
        _state.packet().next_analyzer.reset();
        _state.packet().packet = packet;
        _state.process(len, reinterpret_cast<const char*>(data));
        auto offset = _state.finish();
        assert(offset);
        _state.packet().packet = nullptr;
        _state.packet().packet_val = nullptr;
        _state.reset();
        auto num_processed = offset->Ref();
        const auto& next_analyzer = _state.packet().next_analyzer;
        STATE_DEBUG_MSG(hilti::rt::fmt("processed %" PRIu64 " out of %" PRIu64 " bytes, %s", num_processed, len,
                                       (next_analyzer ? hilti::rt::fmt("next analyzer is 0x%" PRIx32, *next_analyzer) :
                                                        std::string("no next analyzer"))));
        if ( next_analyzer )
            return ForwardPacket(len - num_processed, data + num_processed, packet, *next_analyzer);
        else
            return true;
    } catch ( const hilti::rt::RuntimeError& e ) {
        STATE_DEBUG_MSG(hilti::rt::fmt("error during parsing, triggering analyzer violation: %s", e.what()));
        auto tag = _state.packet().analyzer->GetAnalyzerTag();

        if ( auto* session = packet->session )
            _state.packet().analyzer->AnalyzerViolation(e.what(), session, reinterpret_cast<const char*>(data), len, tag);

        _state.reset();
        return false;
    } catch ( const hilti::rt::Exception& e ) {
        STATE_DEBUG_MSG(e.what());
        reporter::analyzerError(_state.packet().analyzer, e.description(),
                                e.location()); // this sets Zeek to skip sending any further input
        _state.reset();
        return false;
    }
}
