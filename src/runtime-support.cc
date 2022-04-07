// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <memory>

#include <hilti/rt/types/port.h>
#include <hilti/rt/util.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-compat.h>
#include <zeek-spicy/zeek-reporter.h>

#include "zeek/analyzer/Analyzer.h"

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
    auto handler = ::zeek::event_registry->Lookup(name);

    if ( ! handler )
        reporter::internalError(::hilti::rt::fmt("Spicy event %s was not installed", name));

    return handler;
}

void rt::raise_event(const ::zeek::EventHandlerPtr& handler, const hilti::rt::Vector<::zeek::ValPtr>& args,
                     const std::string& location) {
    // Caller must have checked already that there's a handler availale.
    assert(handler);

    const auto zeek_args = const_cast<::zeek::EventHandlerPtr&>(handler)->GetType()->ParamList()->GetTypes();
    if ( args.size() != static_cast<uint64_t>(zeek_args.size()) )
        throw TypeMismatch(hilti::rt::fmt("expected %" PRIu64 " parameters, but got %zu",
                                          static_cast<uint64_t>(zeek_args.size()), args.size()),
                           location);

    ::zeek::Args vl = ::zeek::Args();
    for ( const auto& v : args ) {
        if ( v )
            vl.emplace_back(v);
        else
            // Shouldn't happen here, but we have to_vals() that
            // (legitimately) return null in certain contexts.
            throw InvalidValue("null value encountered after conversion", location);
    }

    ::zeek::event_mgr.Enqueue(handler, vl);
}

::zeek::TypePtr rt::event_arg_type(const ::zeek::EventHandlerPtr& handler,
                                   const hilti::rt::integer::safe<uint64_t>& idx, const std::string& location) {
    assert(handler);

    const auto zeek_args = const_cast<::zeek::EventHandlerPtr&>(handler)->GetType()->ParamList()->GetTypes();
    if ( idx >= static_cast<uint64_t>(zeek_args.size()) )
        throw TypeMismatch(hilti::rt::fmt("more parameters given than the %" PRIu64 " that the Zeek event expects",
                                          static_cast<uint64_t>(zeek_args.size())),
                           location);

    return zeek_args[idx];
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
        return ::zeek::val_mgr->Bool(x->is_orig);
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
        return x->analyzer->GetFile()->ToVal();
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
            c->packet_val = c->packet->ToRawPktHdrVal();

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

std::tuple<hilti::rt::Address, hilti::rt::Port, hilti::rt::Address, hilti::rt::Port> rt::conn_id() {
    static auto convert_address = [](const ::zeek::IPAddr zaddr) -> hilti::rt::Address {
        const uint32_t* bytes = nullptr;
        if ( auto n = zaddr.GetBytes(&bytes); n == 1 )
            // IPv4
            return hilti::rt::Address(*reinterpret_cast<const struct in_addr*>(bytes));
        else if ( n == 4 )
            // IPv6
            return hilti::rt::Address(*reinterpret_cast<const struct in6_addr*>(bytes));
        else
            throw ValueUnavailable("unexpected IP address side from Zeek"); // shouldn't really be able to happen
    };

    static auto convert_port = [](uint32_t port, TransportProto proto) -> hilti::rt::Port {
        auto p = ntohs(static_cast<uint16_t>(port));

        switch ( proto ) {
            case TransportProto::TRANSPORT_ICMP: return {p, hilti::rt::Protocol::ICMP};
            case TransportProto::TRANSPORT_TCP: return {p, hilti::rt::Protocol::TCP};
            case TransportProto::TRANSPORT_UDP: return {p, hilti::rt::Protocol::UDP};
            case TransportProto::TRANSPORT_UNKNOWN: return {p, hilti::rt::Protocol::Undef};
        }

        hilti::rt::cannot_be_reached();
    };

    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        const auto* conn = c->analyzer->Conn();
        return std::make_tuple(convert_address(conn->OrigAddr()), convert_port(conn->OrigPort(), conn->ConnTransport()),
                               convert_address(conn->RespAddr()),
                               convert_port(conn->RespPort(), conn->ConnTransport()));
    }
    else
        throw ValueUnavailable("conn_id() not available in current context");
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

void rt::protocol_begin(const std::optional<std::string>& analyzer) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie);
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    if ( analyzer ) {
        if ( c->analyzer->Conn()->ConnTransport() != TRANSPORT_TCP ) {
            // Some TCP application analyzer may expect to have access to a TCP
            // analyzer. To make that work, we'll create a fake TCP analyzer,
            // just so that they have something to access. It won't
            // semantically have any "TCP" to analyze obviously.
            c->fake_tcp = std::make_shared<::zeek::packet_analysis::TCP::TCPSessionAdapter>(c->analyzer->Conn());
            static_cast<::zeek::analyzer::Analyzer*>(c->fake_tcp.get())
                ->Done(); // will never see packets; cast to get around protected inheritance
        }

        auto child = ::zeek::analyzer_mgr->InstantiateAnalyzer(analyzer->c_str(), c->analyzer->Conn());
        if ( ! child )
            throw ZeekError(::hilti::rt::fmt("unknown analyzer '%s' requested", *analyzer));

        auto* child_as_tcp = dynamic_cast<::zeek::analyzer::tcp::TCP_ApplicationAnalyzer*>(child);
        if ( ! child_as_tcp )
            throw ZeekError(
                ::hilti::rt::fmt("could not add analyzer '%s' to connection; not a TCP-based analyzer", *analyzer));

        if ( ! c->analyzer->AddChildAnalyzer(child) )
            // Child of this type already exists. We ignore this silently
            // because that makes usage nicer if either side of the connection
            // might end up creating the analyzer; this way the user doesn't
            // need to track what the other side already did. Note that
            // AddChildAnalyzer() will have deleted child already, so nothing
            // for us to clean up here.
            return;

        if ( c->fake_tcp )
            child_as_tcp->SetTCP(c->fake_tcp.get());
    }

    else {
        // Use a Zeek PIA stream analyzer performing DPD.
        auto child = new ::zeek::analyzer::pia::PIA_TCP(c->analyzer->Conn());

        if ( ! c->analyzer->AddChildAnalyzer(child) )
            // Same comment as above re/ ignoring the error and memory mgmt.
            return;

        child->FirstPacket(true, nullptr);
        child->FirstPacket(false, nullptr);
    }
}

void rt::protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie);
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    c->analyzer->ForwardStream(data.size(), reinterpret_cast<const u_char*>(data.data()), is_orig);
}

void rt::protocol_gap(const hilti::rt::Bool& is_orig, const hilti::rt::integer::safe<uint64_t>& offset,
                      const hilti::rt::integer::safe<uint64_t>& len) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie);
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    c->analyzer->ForwardUndelivered(is_orig, offset, len);
}

void rt::protocol_end() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie);
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    c->analyzer->ForwardEndOfData(true);
    c->analyzer->ForwardEndOfData(false);

    for ( const auto& i : c->analyzer->GetChildren() )
        c->analyzer->RemoveChildAnalyzer(i);
}

inline rt::cookie::FileStateStack* _file_state_stack(rt::Cookie* cookie) {
    if ( auto c = std::get_if<rt::cookie::ProtocolAnalyzer>(cookie) )
        return c->is_orig ? &c->fstate_orig : &c->fstate_resp;
    else if ( auto f = std::get_if<rt::cookie::FileAnalyzer>(cookie) )
        return &f->fstate;
    else
        throw rt::ValueUnavailable("no current connection or file available");
}

inline const rt::cookie::FileState* _file_state(rt::Cookie* cookie, std::optional<std::string> fid) {
    auto* stack = _file_state_stack(cookie);
    if ( fid ) {
        if ( auto* fstate = stack->find(*fid) )
            return fstate;
        else
            throw rt::ValueUnavailable(hilti::rt::fmt("no file analysis currently in flight for file ID %s", fid));
    }
    else {
        if ( stack->isEmpty() )
            throw rt::ValueUnavailable("no file analysis currently in flight");

        return stack->current();
    }
}

rt::cookie::FileState* rt::cookie::FileStateStack::push() {
    auto fid = ::zeek::file_mgr->HashHandle(hilti::rt::fmt("%s.%d", _analyzer_id, ++_id_counter));
    _stack.emplace_back(fid);
    return &_stack.back();
}

const rt::cookie::FileState* rt::cookie::FileStateStack::find(const std::string& fid) const {
    // Reverse search as the default state would be on top of the stack.
    for ( auto i = _stack.rbegin(); i != _stack.rend(); i++ ) {
        if ( i->fid == fid )
            return &*i;
    }

    return nullptr;
}

void rt::cookie::FileStateStack::remove(const std::string& fid) {
    // Reverse search as the default state would be on top of the stack.
    for ( auto i = _stack.rbegin(); i != _stack.rend(); i++ ) {
        if ( i->fid == fid ) {
            _stack.erase((i + 1).base()); // https://stackoverflow.com/a/1830240
            return;
        }
    }
}

static void _data_in(const char* data, uint64_t len, std::optional<uint64_t> offset,
                     const std::optional<std::string>& fid) {
    auto cookie = static_cast<rt::Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);
    auto data_ = reinterpret_cast<const unsigned char*>(data);
    auto mime_type = (fstate->mime_type ? *fstate->mime_type : std::string());

    if ( auto c = std::get_if<rt::cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());

        if ( offset )
            ::zeek::file_mgr->DataIn(data_, len, *offset, tag, c->analyzer->Conn(), c->is_orig, fstate->fid, mime_type);
        else
            ::zeek::file_mgr->DataIn(data_, len, tag, c->analyzer->Conn(), c->is_orig, fstate->fid, mime_type);
    }
    else {
        if ( offset )
            ::zeek::file_mgr->DataIn(data_, len, *offset, ::spicy::zeek::compat::AnalyzerTag(), nullptr, false,
                                     fstate->fid, mime_type);
        else
            ::zeek::file_mgr->DataIn(data_, len, ::spicy::zeek::compat::AnalyzerTag(), nullptr, false, fstate->fid,
                                     mime_type);
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
    auto* fstate = _file_state_stack(cookie)->push();
    fstate->mime_type = mime_type;

    // Feed an empty chunk into the analysis to force creating the file state inside Zeek.
    _data_in("", 0, {}, {});

    auto file = ::zeek::file_mgr->LookupFile(fstate->fid);
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
        auto rval = file->ToVal()->AsRecordVal();
        auto current = f->analyzer->GetFile()->ToVal()->AsRecordVal();
        rval->Assign(::zeek::id::fa_file->FieldOffset("parent_id"), current->GetField("id")); // set to parent
        rval->Assign(::zeek::id::fa_file->FieldOffset("conns"),
                     current->GetField("conns")); // copy from parent
        rval->Assign(::zeek::id::fa_file->FieldOffset("is_orig"),
                     current->GetField("is_orig")); // copy from parent
    }

    // Double check everybody agrees on the file ID.
    assert(fstate->fid == file->GetID());
    return fstate->fid;
}

void rt::file_set_size(const hilti::rt::integer::safe<uint64_t>& size, const std::optional<std::string>& fid) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());
        ::zeek::file_mgr->SetSize(size, tag, c->analyzer->Conn(), c->is_orig, fstate->fid);
    }
    else
        ::zeek::file_mgr->SetSize(size, ::spicy::zeek::compat::AnalyzerTag(), nullptr, false, fstate->fid);
}

void rt::file_data_in(const hilti::rt::Bytes& data, const std::optional<std::string>& fid) {
    _data_in(data.data(), data.size(), {}, fid);
}

void rt::file_data_in_at_offset(const hilti::rt::Bytes& data, const hilti::rt::integer::safe<uint64_t>& offset,
                                const std::optional<std::string>& fid) {
    _data_in(data.data(), data.size(), offset, fid);
}

void rt::file_gap(const hilti::rt::integer::safe<uint64_t>& offset, const hilti::rt::integer::safe<uint64_t>& len,
                  const std::optional<std::string>& fid) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());
        ::zeek::file_mgr->Gap(offset, len, tag, c->analyzer->Conn(), c->is_orig, fstate->fid);
    }
    else
        ::zeek::file_mgr->Gap(offset, len, ::spicy::zeek::compat::AnalyzerTag(), nullptr, false, fstate->fid);
}

void rt::file_end(const std::optional<std::string>& fid) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);

    ::zeek::file_mgr->EndOfFile(fstate->fid);
    _file_state_stack(cookie)->remove(fstate->fid);
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
    return hilti::rt::Time(::zeek::run_state::network_time, hilti::rt::Time::SecondTag());
}
