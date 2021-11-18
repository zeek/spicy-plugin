// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/util.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-compat.h>
#include <zeek-spicy/zeek-reporter.h>

using namespace spicy::zeek;
using namespace plugin::Zeek_Spicy;

void rt::register_protocol_analyzer(const std::string& name, hilti::rt::Protocol proto,
                                    const hilti::rt::Vector<hilti::rt::Port>& ports, const std::string& parser_orig,
                                    const std::string& parser_resp, const std::string& replaces,
                                    const std::string& linker_scope) {
    OurPlugin->registerProtocolAnalyzer(name, proto, ports, parser_orig, parser_resp, replaces, linker_scope);
}

void rt::register_file_analyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                                const std::string& parser, const std::string& replaces,
                                const std::string& linker_scope) {
    OurPlugin->registerFileAnalyzer(name, mime_types, parser, replaces, linker_scope);
}

void rt::register_packet_analyzer(const std::string& name, const std::string& parser, const std::string& linker_scope) {
#ifdef HAVE_PACKET_ANALYZERS
    OurPlugin->registerPacketAnalyzer(name, parser, linker_scope);
#else
    throw Unsupported("packet analyzer functionality requires Zeek >= 4.0");
#endif
}

void rt::register_enum_type(
    const std::string& ns, const std::string& id,
    const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels) {
    OurPlugin->registerEnumType(ns, id, labels);
    OurPlugin->AddBifItem(::hilti::rt::fmt("%s::%s", ns, id), ::zeek::plugin::BifItem::TYPE);
}

void rt::install_handler(const std::string& name) { OurPlugin->registerEvent(name); }

::zeek::EventHandlerPtr rt::internal_handler(const std::string& name) {
    auto handler = zeek::compat::event_register_Lookup(name);

    if ( ! handler )
        reporter::internalError(::hilti::rt::fmt("Spicy event %s was not installed", name));

    return handler;
}

void rt::raise_event(const ::zeek::EventHandlerPtr& handler, const hilti::rt::Vector<::zeek::ValPtr>& args,
                     const std::string& location) {
    // Caller must have checked already that there's a handler availale.
    assert(handler);

    auto zeek_args =
        zeek::compat::TypeList_GetTypes(zeek::compat::FuncType_ArgTypes(compat::EventHandler_GetType(handler)));
    if ( args.size() != zeek::compat::TypeList_GetTypesSize(zeek_args) )
        throw TypeMismatch(hilti::rt::fmt("expected %" PRIu64 " parameters, but got %zu",
                                          zeek::compat::TypeList_GetTypesSize(zeek_args), args.size()),
                           location);

    ::zeek::Args vl = zeek::compat::ZeekArgs_New();
    for ( const auto& v : args ) {
        if ( v )
            zeek::compat::ZeekArgs_Append(vl, v);
        else
            // Shouldn't happen here, but we have to_vals() that
            // (legitimately) return null in certain contexts.
            throw InvalidValue("null value encountered after conversion", location);
    }

    zeek::compat::event_mgr_Enqueue(handler, vl);
}

::zeek::TypePtr rt::event_arg_type(const ::zeek::EventHandlerPtr& handler,
                                   const hilti::rt::integer::safe<uint64_t>& idx, const std::string& location) {
    assert(handler);

    auto zeek_args =
        zeek::compat::TypeList_GetTypes(zeek::compat::FuncType_ArgTypes(compat::EventHandler_GetType(handler)));
    if ( idx >= static_cast<uint64_t>(zeek::compat::TypeList_GetTypesSize(zeek_args)) )
        throw TypeMismatch(hilti::rt::fmt("more parameters given than the %" PRIu64 " that the Zeek event expects",
                                          zeek::compat::TypeList_GetTypesSize(zeek_args)),
                           location);

    return zeek::compat::ZeekArgs_Get(zeek_args, idx);
}

::zeek::ValPtr rt::current_conn(const std::string& location) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return zeek::compat::Connection_ConnVal(x->analyzer->Conn());
    else
        throw ValueUnavailable("$conn not available", location);
}

::zeek::ValPtr rt::current_is_orig(const std::string& location) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return zeek::compat::val_mgr_Bool(x->is_orig);
    else
        throw ValueUnavailable("$is_orig not available", location);
}

void rt::debug(const std::string& msg) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);
    rt::debug(*cookie, msg);
}

void rt::debug(const Cookie& cookie, const std::string& msg) {
    std::string name;
    std::string id;

    if ( const auto p = std::get_if<cookie::ProtocolAnalyzer>(&cookie) ) {
        auto name = p->analyzer->GetAnalyzerName();
        ZEEK_DEBUG(
            hilti::rt::fmt("[%s/%" PRIu32 "/%s] %s", name, p->analyzer->GetID(), (p->is_orig ? "orig" : "resp"), msg));
    }
    else if ( const auto f = std::get_if<cookie::FileAnalyzer>(&cookie) ) {
        auto name = ::zeek::file_mgr->GetComponentName(f->analyzer->Tag());
        ZEEK_DEBUG(hilti::rt::fmt("[%s/%" PRIu32 "] %s", name, f->analyzer->GetID(), msg));
    }
#ifdef HAVE_PACKET_ANALYZERS
    else if ( const auto f = std::get_if<cookie::PacketAnalyzer>(&cookie) ) {
        auto name = ::zeek::packet_mgr->GetComponentName(f->analyzer->GetAnalyzerTag());
        ZEEK_DEBUG(hilti::rt::fmt("[%s] %s", name, msg));
    }
#endif
    else
        throw ValueUnavailable("neither $conn nor $file nor packet analyzer available for debug logging");
}

::zeek::ValPtr rt::current_file(const std::string& location) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::FileAnalyzer>(cookie) )
        return zeek::compat::File_ToVal(x->analyzer->GetFile());
    else
        throw ValueUnavailable("$file not available", location);
}

::zeek::ValPtr rt::current_packet(const std::string& location) {
#ifdef HAVE_PACKET_ANALYZERS
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::PacketAnalyzer>(cookie) ) {
        if ( ! c->packet_val )
            // We cache the built value in case we need it multiple times.
            c->packet_val = zeek::compat::Packet_ToRawPktHdrVal(c->packet);

        return c->packet_val;
    }
    else
        throw ValueUnavailable("$packet not available", location);
#else
    throw Unsupported("packet analyzer functionality requires Zeek >= 4.0");
#endif
}

hilti::rt::Bool rt::is_orig() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return x->is_orig;
    else
        throw ValueUnavailable("is_orig() not available in current context");
}
std::string rt::uid() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return c->analyzer->Conn()->GetUID().Base62("C");
    else
        throw ValueUnavailable("uid() not available in current context");
}

void rt::flip_roles() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    rt::debug(*cookie, "flipping roles");

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        x->analyzer->Conn()->FlipRoles();
    else
        throw ValueUnavailable("flip_roles() not available in current context");
}

hilti::rt::integer::safe<uint64_t> rt::number_packets() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        return x->num_packets;
    }
    else
        throw ValueUnavailable("number_packets() not available in current context");
}

void rt::confirm_protocol() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        return x->analyzer->ProtocolConfirmation(tag);
    }
    else
        throw ValueUnavailable("no current connection available");
}

void rt::reject_protocol(const std::string& reason) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return x->analyzer->ProtocolViolation(reason.c_str());
    else
        throw ValueUnavailable("no current connection available");
}

inline rt::cookie::FileState* _file_state(rt::Cookie* cookie) {
    if ( auto c = std::get_if<rt::cookie::ProtocolAnalyzer>(cookie) )
        return c->is_orig ? &c->fstate_orig : &c->fstate_resp;
    else if ( auto f = std::get_if<rt::cookie::FileAnalyzer>(cookie) )
        return &f->fstate;
    else
        throw rt::ValueUnavailable("no current connection or file available");
}

static std::string _file_id(rt::Cookie* cookie) {
    assert(cookie);
    return _file_state(cookie)->id();
}

static void _data_in(const char* data, uint64_t len, std::optional<uint64_t> offset = {}) {
    auto cookie = static_cast<rt::Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie);
    auto fid = fstate->id();
    auto data_ = reinterpret_cast<const unsigned char*>(data);
    auto mime_type = (fstate->mime_type ? *fstate->mime_type : std::string());

    if ( auto c = std::get_if<rt::cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());

        if ( offset )
            ::zeek::file_mgr->DataIn(data_, len, *offset, tag, c->analyzer->Conn(), c->is_orig, fid, mime_type);
        else
            ::zeek::file_mgr->DataIn(data_, len, tag, c->analyzer->Conn(), c->is_orig, fid, mime_type);
    }
    else {
        if ( offset )
            ::zeek::file_mgr->DataIn(data_, len, *offset, ::zeek::analyzer::Tag(), nullptr, false, fid, mime_type);
        else
            ::zeek::file_mgr->DataIn(data_, len, ::zeek::analyzer::Tag(), nullptr, false, fid, mime_type);
    }
}

std::string rt::fuid() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto f = std::get_if<cookie::FileAnalyzer>(cookie) ) {
        if ( auto file = f->analyzer->GetFile() )
            return file->GetID();
    }

    throw ValueUnavailable("fuid() not available in current context");
}

std::string rt::file_begin(const std::optional<std::string>& mime_type) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie);
    ++fstate->file_id;
    fstate->mime_type = mime_type;

    // Feed an empty chunk into the analysis to force creating the file state inside Zeek.
    _data_in("", 0);

    auto fid = _file_id(cookie);
    auto file = ::zeek::file_mgr->LookupFile(fid);
    assert(file); // passing in empty data ensures that this is now available

    if ( auto f = std::get_if<rt::cookie::FileAnalyzer>(cookie) ) {
        // We need to initialize some fa_info fields ourselves that would
        // normally be inferred from the connection.

        // Set the source to the current file analyzer.
        file->SetSource(::zeek::file_mgr->GetComponentName(f->analyzer->Tag()));

        // There are some fields inside the new fa_info record that we want to
        // set, but don't have a Zeek API for. Hence, we need to play some
        // tricks: we can get to the fa_info value, but read-only; const_cast
        // comes to our rescue. And then we just write directly into the
        // record fields.
        auto rval = const_cast<::zeek::RecordVal*>(zeek::compat::File_ToVal(file)->AsRecordVal());
        auto current = zeek::compat::File_ToVal(f->analyzer->GetFile())->AsRecordVal();
        rval->Assign(::zeek::id::fa_file->FieldOffset("parent_id"),
                     zeek::compat::RecordVal_GetField(current, "id")); // set to parent
        rval->Assign(::zeek::id::fa_file->FieldOffset("conns"),
                     zeek::compat::RecordVal_GetField(current, "conns")); // copy from parent
        rval->Assign(::zeek::id::fa_file->FieldOffset("is_orig"),
                     zeek::compat::RecordVal_GetField(current, "is_orig")); // copy from parent
    }


    return file->GetID();
}

void rt::file_set_size(const hilti::rt::integer::safe<uint64_t>& size) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto fid = _file_id(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());
        ::zeek::file_mgr->SetSize(size, tag, c->analyzer->Conn(), c->is_orig, fid);
    }
    else
        ::zeek::file_mgr->SetSize(size, ::zeek::analyzer::Tag(), nullptr, false, fid);
}

void rt::file_data_in(const hilti::rt::Bytes& data) { _data_in(data.data(), data.size()); }

void rt::file_data_in_at_offset(const hilti::rt::Bytes& data, const hilti::rt::integer::safe<uint64_t>& offset) {
    _data_in(data.data(), data.size(), offset);
}

void rt::file_gap(const hilti::rt::integer::safe<uint64_t>& offset, const hilti::rt::integer::safe<uint64_t>& len) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto fid = _file_id(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());
        ::zeek::file_mgr->Gap(offset, len, tag, c->analyzer->Conn(), c->is_orig, fid);
    }
    else
        ::zeek::file_mgr->Gap(offset, len, ::zeek::analyzer::Tag(), nullptr, false, fid);
}

void rt::file_end() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto fid = _file_id(cookie);

    ::zeek::file_mgr->EndOfFile(_file_id(cookie));
}

void rt::forward_packet(const hilti::rt::integer::safe<uint32_t>& identifier) {
#ifdef HAVE_PACKET_ANALYZERS
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::PacketAnalyzer>(cookie) )
        c->next_analyzer = identifier;
    else
        throw ValueUnavailable("no current packet analyzer available");
#else
    throw Unsupported("packet analyzer functionality requires Zeek >= 4.0");
#endif
}

hilti::rt::Time rt::network_time() {
    return hilti::rt::Time(zeek::compat::networkTime(), hilti::rt::Time::SecondTag());
}
