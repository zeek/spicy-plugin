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

#if ZEEK_VERSION_NUMBER < 40000
#error "Zeek version must be >= 4.0"
#endif

//// Collect all the Zeek includes here that we need anywhere in the plugin.

#if ZEEK_DEBUG_BUILD
#ifndef DEBUG
#define DEBUG
#endif
#endif

#include <zeek/packet_analysis/Analyzer.h>

#if ZEEK_VERSION_NUMBER >= 40200
#include <zeek/Tag.h>
#else
#include <zeek/analyzer/Tag.h>
#include <zeek/file_analysis/Tag.h>
#include <zeek/packet_analysis/Tag.h>
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
#include <zeek/Type.h>
#include <zeek/Val.h>
#include <zeek/Var.h>
#include <zeek/analyzer/Analyzer.h>
#include <zeek/analyzer/Manager.h>
#include <zeek/analyzer/protocol/pia/PIA.h>
#include <zeek/analyzer/protocol/tcp/TCP.h>
#if ZEEK_VERSION_NUMBER < 40100 // Zeek < 4.1
#include <zeek/analyzer/protocol/udp/UDP.h>
#endif
#include <zeek/file_analysis/Analyzer.h>
#include <zeek/file_analysis/File.h>
#include <zeek/file_analysis/Manager.h>
#include <zeek/module_util.h>
#include <zeek/plugin/Plugin.h>

#undef DEBUG

//// Import types and globals into the new namespaces.

#if ZEEK_VERSION_NUMBER < 40100 // Zeek < 4.1
namespace zeek::packet_analysis::TCP {
using TCPSessionAdapter = ::zeek::analyzer::tcp::TCP_Analyzer;
} // namespace zeek::packet_analysis::TCP
#endif

//// Wrappers for functionality that differs by version.

namespace spicy::zeek::compat {
#if ZEEK_VERSION_NUMBER < 40200 // Zeek < 4.2
using AnalyzerTag = ::zeek::analyzer::Tag;
using FileAnalysisTag = ::zeek::file_analysis::Tag;

using PacketAnalysisTag = ::zeek::packet_analysis::Tag;
#else
class AnalyzerTag : public ::zeek::Tag {
public:
    using ::zeek::Tag::Tag;
    AnalyzerTag(::zeek::Tag t) : ::zeek::Tag(std::move(t)){};
};

class FileAnalysisTag : public ::zeek::Tag {
public:
    using ::zeek::Tag::Tag;
    FileAnalysisTag(::zeek::Tag t) : ::zeek::Tag(std::move(t)){};
};

class PacketAnalysisTag : public ::zeek::Tag {
public:
    using ::zeek::Tag::Tag;
    PacketAnalysisTag(::zeek::Tag t) : ::zeek::Tag(std::move(t)){};
};
#endif

} // namespace spicy::zeek::compat

namespace spicy::zeek::compat {

#if ZEEK_VERSION_NUMBER >= 40100 // Zeek >= 4.1
inline auto Connection_ConnVal(::zeek::Connection* c) { return c->GetVal(); }
#else
inline auto Connection_ConnVal(::zeek::Connection* c) { return c->ConnVal(); }
#endif

} // namespace spicy::zeek::compat
