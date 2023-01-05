// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// Provides backwards compatibility for older Zeek versions.

#pragma once

#include <zeek/zeek-config.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <zeek-spicy/autogen/config.h>

#ifdef ZEEK_VERSION_NUMBER
#if ZEEK_SPICY_VERSION_NUMBER != ZEEK_VERSION_NUMBER
#define STR(x) __STR(x)
#define __STR(x) #x
#pragma message "Zeek version " STR(ZEEK_SPICY_VERSION_NUMBER) " vs " STR(ZEEK_VERSION_NUMBER) ")"
#error "Mismatch in Zeek version numbers"
#undef __STR
#undef STR
#endif
#endif

//// Collect all the Zeek includes here that we need anywhere in the plugin.

#if ZEEK_DEBUG_BUILD
#ifndef DEBUG
#define DEBUG
#endif
#endif

#include <zeek/Conn.h>
#include <zeek/DebugLogger.h>
#include <zeek/Desc.h>
#include <zeek/Event.h>
#include <zeek/EventHandler.h>
#include <zeek/EventRegistry.h>
#include <zeek/Expr.h>
#include <zeek/IPAddr.h>
#include <zeek/Reporter.h>
#include <zeek/Tag.h>
#include <zeek/Type.h>
#include <zeek/Val.h>
#include <zeek/Var.h>
#include <zeek/analyzer/Analyzer.h>
#include <zeek/analyzer/Manager.h>
#include <zeek/analyzer/protocol/pia/PIA.h>
#include <zeek/analyzer/protocol/tcp/TCP.h>
#include <zeek/file_analysis/Analyzer.h>
#include <zeek/file_analysis/File.h>
#include <zeek/file_analysis/Manager.h>
#include <zeek/module_util.h>
#include <zeek/packet_analysis/Analyzer.h>
#include <zeek/plugin/Plugin.h>
#include <zeek/session/Manager.h>

#undef DEBUG

//// Import types and globals into the new namespaces.

#if ZEEK_VERSION_NUMBER < 50100 // Zeek < 5.1
using zeek_int_t = bro_int_t;
#endif

//// Wrappers for functionality that differs by version.

namespace spicy::zeek::compat {
class AnalyzerTag : public ::zeek::Tag {
public:
    using ::zeek::Tag::Tag;
    AnalyzerTag(::zeek::Tag t) : ::zeek::Tag(std::move(t)) {}
};

class FileAnalysisTag : public ::zeek::Tag {
public:
    using ::zeek::Tag::Tag;
    FileAnalysisTag(::zeek::Tag t) : ::zeek::Tag(std::move(t)) {}
};

class PacketAnalysisTag : public ::zeek::Tag {
public:
    using ::zeek::Tag::Tag;
    PacketAnalysisTag(::zeek::Tag t) : ::zeek::Tag(std::move(t)) {}
};

} // namespace spicy::zeek::compat

namespace spicy::zeek::compat {

// Version-specific implementation for AnalyzerConfirmation().
inline void Analyzer_AnalyzerConfirmation(::zeek::analyzer::Analyzer* analyzer, const AnalyzerTag& tag) {
    analyzer->AnalyzerConfirmation(tag);
}

inline void Analyzer_AnalyzerViolation(::zeek::analyzer::Analyzer* analyzer, const char* reason, const char* data,
                                       int len, const ::zeek::Tag& tag) {
    analyzer->AnalyzerViolation(reason, data, len, tag);
}

inline void Analyzer_AnalyzerViolation(const ::zeek::Packet& packet, ::zeek::packet_analysis::Analyzer* analyzer,
                                       const char* reason, const char* data, int len, const ::zeek::Tag& tag) {
    if ( auto* session = packet.session )
        analyzer->AnalyzerViolation(reason, session, data, len, tag);
}

inline void Analyzer_AnalyzerViolation(::zeek::file_analysis::Analyzer* analyzer, const char* reason, const char* data,
                                       int len, const ::zeek::Tag& tag) {
    // We do not a have good way to report this in any Zeek version.
}

inline void PacketAnalyzer_Weird(::zeek::packet_analysis::Analyzer* analyzer, const char* name, ::zeek::Packet* packet,
                                 const char* addl) {
    analyzer->Weird(name, packet, addl);
}

inline auto Connection_ConnVal(::zeek::Connection* c) { return c->GetVal(); }
inline void SessionMgr_Remove(::zeek::Connection* c) {
    assert(::zeek::session_mgr);
    ::zeek::session_mgr->Remove(c);
}

} // namespace spicy::zeek::compat
