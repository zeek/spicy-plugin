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

inline AnalyzerTag analyzer_mgr_AnalyzerTag(const char* name) { return ::zeek::analyzer_mgr->GetAnalyzerTag(name); }
inline AnalyzerTag ComponentTag(const ::zeek::analyzer::Component& component) { return component.Tag(); }
inline FileAnalysisTag ComponentTag(const ::zeek::file_analysis::Component& component) { return component.Tag(); }
inline PacketAnalysisTag ComponentTag(const ::zeek::packet_analysis::Component& component) { return component.Tag(); }
} // namespace spicy::zeek::compat

namespace spicy::zeek::compat {

inline auto AddrVal_New(const std::string& x) { return ::zeek::make_intrusive<::zeek::AddrVal>(x); }
inline auto DoubleVal_New(double x) { return ::zeek::make_intrusive<::zeek::DoubleVal>(x); }
inline auto IntervalVal_New(double x) { return ::zeek::make_intrusive<::zeek::IntervalVal>(x); }
inline auto StringVal_New(const std::string& x) { return ::zeek::make_intrusive<::zeek::StringVal>(x); }
inline auto TimeVal_New(double x) { return ::zeek::make_intrusive<::zeek::TimeVal>(x); }
inline auto EnumType_New(std::string& x) { return ::zeek::make_intrusive<::zeek::EnumType>(x); }

// Helper to create an event type taking no arguments.
inline auto EventTypeDummy_New() {
    auto args = ::zeek::make_intrusive<::zeek::RecordType>(new ::zeek::type_decl_list());
    return ::zeek::make_intrusive<::zeek::FuncType>(std::move(args), ::zeek::base_type(::zeek::TYPE_VOID),
                                                    ::zeek::FUNC_FLAVOR_EVENT);
}

template<typename T>
inline auto ToValPtr(std::unique_ptr<T> p) {
    return ::zeek::IntrusivePtr{::zeek::AdoptRef{}, p.release()};
}

template<typename T>
inline auto ToValCtorType(T p) {
    return ::zeek::IntrusivePtr{::zeek::NewRef{}, p};
}

template<typename T>
inline auto Unref(const ::zeek::IntrusivePtr<T>& o) {
    // nothing to do
}

inline auto Attribute_Find(::zeek::IntrusivePtr<::zeek::detail::Attributes> a, ::zeek::detail::AttrTag x) {
    return a->Find(x);
}

#if ZEEK_VERSION_NUMBER >= 40100 // Zeek >= 4.1
inline auto Connection_ConnVal(::zeek::Connection* c) { return c->GetVal(); }
#else
inline auto Connection_ConnVal(::zeek::Connection* c) { return c->ConnVal(); }
#endif

inline auto AnalyzerMgr_GetTagType() { return ::zeek::analyzer_mgr->GetTagType(); }
inline auto EnumTypeGetEnumVal(::zeek::EnumType* t, ::bro_int_t i) { return t->GetEnumVal(i); }
inline auto EnumVal_GetType(::zeek::EnumVal* v) { return v->GetType(); }
inline auto EventHandler_GetType(::zeek::EventHandlerPtr ev, bool check_export = true) {
    return ev->GetType(check_export);
}
inline auto FileAnalysisComponentTag_AsVal(const FileAnalysisTag& t) { return t.AsVal(); }
inline auto FileMgr_GetTagType() { return ::zeek::file_mgr->GetTagType(); }
inline auto File_ToVal(::zeek::file_analysis::File* f) { return f->ToVal(); }
inline auto FuncType_ArgTypes(::zeek::FuncTypePtr f) { return f->ParamList(); }
inline auto ID_GetType(::zeek::detail::IDPtr id) { return id->GetType(); }
inline auto RecordType_GetFieldType(::zeek::RecordType* t, int i) { return t->GetFieldType(i); }
inline auto RecordVal_GetField(::zeek::RecordVal* v, const char* field) { return v->GetField(field); }
inline auto TableType_GetIndexTypes(::zeek::TableType* tt) { return tt->GetIndexTypes(); }
inline auto TableType_GetIndexTypesLength(::zeek::TableType* tt) { return tt->GetIndexTypes().size(); }
inline auto TableType_Yield(::zeek::TableType* t) { return t->Yield(); }
inline auto TypeList_GetTypes(::zeek::TypeListPtr l) { return l->GetTypes(); }
inline auto Val_GetTypeTag(const ::zeek::Val* v) { return v->GetType()->Tag(); }
inline auto VectorType_Yield(::zeek::VectorType* t) { return t->Yield(); }
inline auto ZeekArgs_New() { return ::zeek::Args(); }
inline auto ZeekArgs_Append(::zeek::Args& args, ::zeek::ValPtr v) { args.emplace_back(std::move(v)); }
inline auto ZeekArgs_Get(const std::vector<::zeek::TypePtr>& vl, uint64_t idx) { return vl[idx]; }
inline auto event_mgr_Enqueue(const ::zeek::EventHandlerPtr& h, ::zeek::Args vl) {
    return ::zeek::event_mgr.Enqueue(h, std::move(vl));
}
inline auto event_register_Register(const std::string& x) { return ::zeek::event_registry->Register(x); }
inline auto event_register_Lookup(const std::string& x) { return ::zeek::event_registry->Lookup(x); }
inline auto Packet_ToRawPktHdrVal(::zeek::Packet* packet) { return packet->ToRawPktHdrVal(); }
inline auto val_mgr_Bool(bool b) { return ::zeek::val_mgr->Bool(b); }
inline auto val_mgr_Count(uint64_t i) { return ::zeek::val_mgr->Count(i); }
inline auto val_mgr_Int(int64_t i) { return ::zeek::val_mgr->Int(i); }
inline auto val_mgr_Port(uint32_t p, TransportProto t) { return ::zeek::val_mgr->Port(p, t); }
inline auto TypeList_GetTypesSize(const std::vector<::zeek::TypePtr>& t) { return static_cast<uint64_t>(t.size()); }

inline auto networkTime() { return ::zeek::run_state::network_time; }

} // namespace spicy::zeek::compat
