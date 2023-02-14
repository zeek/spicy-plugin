// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

/**
 * Functions and types available to generated Spicy/Zeek glue code.
 */

#pragma once

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include <hilti/rt/deferred-expression.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/types/all.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/cookie.h>
#include <zeek-spicy/zeek-compat.h>

namespace spicy::zeek::rt {

/**
 * Exception thrown by event generation code if the value of an `$...`
 * expression isn't available.
 */
class ValueUnavailable : public hilti::rt::UserException {
public:
    using hilti::rt::UserException::UserException;
};

/**
 * Exception thrown by event generation code if the values can't be converted
 * to Zeek.
 */
class InvalidValue : public hilti::rt::UserException {
public:
    using hilti::rt::UserException::UserException;
};

/**
 * Exception thrown by event generation code if functionality is used
 * that the current build does not support.
 */
class Unsupported : public hilti::rt::UserException {
public:
    using hilti::rt::UserException::UserException;
};

/**
 * Exception thrown by event generation code if there's a type mismatch
 * between the Spicy-side value and what the Zeek event expects.
 */
class TypeMismatch : public hilti::rt::UserException {
public:
    TypeMismatch(const std::string_view& msg, std::string_view location = "")
        : hilti::rt::UserException(hilti::rt::fmt("Event parameter mismatch, %s", msg), location) {}
    TypeMismatch(const std::string_view& have, ::zeek::TypePtr want, std::string_view location = "")
        : TypeMismatch(_fmt(have, want), location) {}

private:
    std::string _fmt(const std::string_view& have, ::zeek::TypePtr want) {
        ::zeek::ODesc d;
        want->Describe(&d);
        return hilti::rt::fmt("cannot convert Spicy value of type '%s' to Zeek value of type '%s'", have,
                              d.Description());
    }
};

/**
 * Exception thrown by the runtime library when Zeek has flagged a problem.
 */
class ZeekError : public hilti::rt::UserException {
public:
    using hilti::rt::UserException::UserException;
};

/**
 * Registers a Spicy protocol analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_protocol_analyzer(const std::string& name, hilti::rt::Protocol proto,
                                const hilti::rt::Vector<hilti::rt::Port>& ports, const std::string& parser_orig,
                                const std::string& parser_resp, const std::string& replaces,
                                const std::string& linker_scope);

/**
 * Registers a Spicy file analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_file_analyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                            const std::string& parser, const std::string& replaces, const std::string& linker_scope);

/** Reports a Zeek-side "weird". */
void weird(const std::string& id, const std::string& addl);

/**
 * Registers a Spicy packet analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_packet_analyzer(const std::string& name, const std::string& parser, const std::string& linker_scope);

/** Registers a Spicy enum type to make it available inside Zeek. */
void register_enum_type(const std::string& ns, const std::string& id,
                        const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels);

/** Returns true if an event has at least one handler defined. */
inline hilti::rt::Bool have_handler(const ::zeek::EventHandlerPtr& handler) { return static_cast<bool>(handler); }

/**
 * Creates a new event handler under the given name.
 */
void install_handler(const std::string& name);

/**
 * Looks up an event handler by name. The handler must have been installed
 * before through `install_handler()`.
 */
::zeek::EventHandlerPtr internal_handler(const std::string& name);

/** Raises a Zeek event, given the handler and arguments. */
void raise_event(const ::zeek::EventHandlerPtr& handler, const hilti::rt::Vector<::zeek::ValPtr>& args,
                 const std::string& location);

/**
 * Returns the Zeek type of an event's i'th argument. The result's ref count
 * is not increased.
 */
::zeek::TypePtr event_arg_type(const ::zeek::EventHandlerPtr& handler, const hilti::rt::integer::safe<uint64_t>& idx,
                               const std::string& location);

/**
 * Retrieves the connection ID for the currently processed Zeek connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
::zeek::ValPtr current_conn(const std::string& location);

/**
 * Retrieves the direction of the currently processed Zeek connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of boolean type
 */
::zeek::ValPtr current_is_orig(const std::string& location);

/**
 * Logs a string through the Spicy plugin's debug output.
 *
 * @param cookie refers to the connection or file that the message is associated with
 * @param msg message to log
 */
void debug(const Cookie& cookie, const std::string& msg);

/**
 * Logs a string through the Spicy plugin's debug output. This version logs
 * the information the currently processed connection or file.
 *
 * @param msg message to log
 */
void debug(const std::string& msg);

/**
 * Retrieves the fa_file instance for the currently processed Zeek file.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
::zeek::ValPtr current_file(const std::string& location);

/**
 * Retrieves a `raw_pkt_hdr` instance for the currently processed Zeek packet.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
::zeek::ValPtr current_packet(const std::string& location);

/**
 * Returns true if we're currently parsing the originator side of a
 * connection.
 */
hilti::rt::Bool is_orig();

/**
 * Returns the current connection's UID.
 */
std::string uid();

/**
 * Returns the current connection's ID tuple.
 */
std::tuple<hilti::rt::Address, hilti::rt::Port, hilti::rt::Address, hilti::rt::Port> conn_id();

/** Instructs to Zeek to flip the directionality of the current connecction. */
void flip_roles();

/**
 * Returns the number of packets seen so far on the current side of the
 * current connection.
 */
hilti::rt::integer::safe<uint64_t> number_packets();

/**
 * Triggers a DPD protocol confirmation for the currently processed
 * connection. Assumes that the HILTI context's cookie value has been set
 * accordingly.
 */
void confirm_protocol();

/**
 * Triggers a DPD protocol violation for the currently processed connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @param reason short description of what went wrong
 */
void reject_protocol(const std::string& reason);

/**
 * Adds a Zeek-side child protocol analyzer to the current connection.
 *
 * @param analyzer if given, the Zeek-side name of the analyzer to instantiate;
 * if not given, DPD will be used
 */
void protocol_begin(const std::optional<std::string>& analyzer);

/**
 * Forwards data to all previously instantiated Zeek-side child protocol
 * analyzers.
 *
 * @param is_orig true to feed data to originator side, false for responder
 * @param data next chunk of stream data for child analyzer to process
 */
void protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data);

/**
 * Signals a gap in input data to all previously instantiated Zeek-side child
 * protocol analyzers.
 *
 * @param is_orig true to signal gap to originator side, false for responder
 * @param offset of the gap inside the protocol stream
 * @param length of the gap
 */
void protocol_gap(const hilti::rt::Bool& is_orig, const hilti::rt::integer::safe<uint64_t>& offset,
                  const hilti::rt::integer::safe<uint64_t>& len);

/**
 * Signals EOD to all previously instantiated Zeek-side child protocol
 * analyzers and removes them.
 *
 * @param analyzer ID of analyzer previously instantiated through `protocol_begin()`.
 */
void protocol_end();

/**
 * Signals the beginning of a file to Zeek's file analysis, associating it
 * with the current connection.
 *
 * param mime_type optional mime type passed to Zeek
 * @returns Zeek-side file ID of the new file
 */
std::string file_begin(const std::optional<std::string>& mime_type);

/**
 * Returns the current file's FUID.
 */
std::string fuid();

/**
 * Terminates the currently active Zeek-side session, flushing all state. Any
 * subsequent activity will start a new session from scratch.
 */
void terminate_session();

/**
 * Signals the expected size of a file to Zeek's file analysis.
 *
 * @param size expected final size of the file
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_set_size(const hilti::rt::integer::safe<uint64_t>& size, const std::optional<std::string>& fid = {});

/**
 * Passes file content on to Zeek's file analysis.
 *
 * @param data next chunk of data
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_data_in(const hilti::rt::Bytes& data, const std::optional<std::string>& fid = {});

/**
 * Passes file content at a specific offset on to Zeek's file analysis.
 *
 * @param data next chunk of data
 * @param offset file offset of the data geing passed in
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_data_in_at_offset(const hilti::rt::Bytes& data, const hilti::rt::integer::safe<uint64_t>& offset,
                            const std::optional<std::string>& fid = {});

/**
 * Signals a gap in a file to Zeek's file analysis.
 *
 * @param offset of the gap
 * @param length of the gap
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_gap(const hilti::rt::integer::safe<uint64_t>& offset, const hilti::rt::integer::safe<uint64_t>& len,
              const std::optional<std::string>& fid = {});

/**
 * Signals the end of a file to Zeek's file analysis.
 *
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_end(const std::optional<std::string>& fid = {});

/** Specifies the next-layer packet analyzer. */
void forward_packet(const hilti::rt::integer::safe<uint32_t>& identifier);

/** Gets the network time from Zeek. */
hilti::rt::Time network_time();

// Forward-declare to_val() functions.
template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>* = nullptr>
::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, const std::string& location);
template<typename T, typename std::enable_if_t<std::is_base_of<::hilti::rt::trait::isStruct, T>::value>* = nullptr>
::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, const std::string& location);
template<typename T, typename std::enable_if_t<std::is_enum<T>::value>* = nullptr>
::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, const std::string& location);
template<typename K, typename V>
::zeek::ValPtr to_val(const hilti::rt::Map<K, V>& s, ::zeek::TypePtr target, const std::string& location);
template<typename T>
::zeek::ValPtr to_val(const hilti::rt::Set<T>& s, ::zeek::TypePtr target, const std::string& location);
template<typename T>
::zeek::ValPtr to_val(const hilti::rt::Vector<T>& v, ::zeek::TypePtr target, const std::string& location);
template<typename T>
::zeek::ValPtr to_val(const std::optional<T>& t, ::zeek::TypePtr target, const std::string& location);
template<typename T>
::zeek::ValPtr to_val(const hilti::rt::DeferredExpression<T>& t, ::zeek::TypePtr target, const std::string& location);
template<typename T>
::zeek::ValPtr to_val(hilti::rt::integer::safe<T> i, ::zeek::TypePtr target, const std::string& location);
template<typename T>
::zeek::ValPtr to_val(const hilti::rt::ValueReference<T>& t, ::zeek::TypePtr target, const std::string& location);

inline ::zeek::ValPtr to_val(const hilti::rt::Bool& b, ::zeek::TypePtr target, const std::string& location);
inline ::zeek::ValPtr to_val(const hilti::rt::Address& d, ::zeek::TypePtr target, const std::string& location);
inline ::zeek::ValPtr to_val(const hilti::rt::Bytes& b, ::zeek::TypePtr target, const std::string& location);
inline ::zeek::ValPtr to_val(const hilti::rt::Interval& t, ::zeek::TypePtr target, const std::string& location);
inline ::zeek::ValPtr to_val(const hilti::rt::Port& d, ::zeek::TypePtr target, const std::string& location);
inline ::zeek::ValPtr to_val(const hilti::rt::Time& t, ::zeek::TypePtr target, const std::string& location);
inline ::zeek::ValPtr to_val(const std::string& s, ::zeek::TypePtr target, const std::string& location);
inline ::zeek::ValPtr to_val(double r, ::zeek::TypePtr target, const std::string& location);

/**
 * Converts a Spicy-side optional value to a Zeek value. This assumes the
 * optional is set, and will throw an exception if not. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(const std::optional<T>& t, ::zeek::TypePtr target, const std::string& location) {
    if ( t.has_value() )
        return to_val(hilti::rt::optional::value(t, location.data()), target, location);

    return nullptr;
}

/**
 * Converts a Spicy-side DeferredExpression<T> value to a Zeek value. Such
 * result values are returned by the ``.?`` operator. If the result is not
 * set, this will convert into nullptr (which the tuple-to-record to_val()
 * picks up on).
 */
template<typename T>
inline ::zeek::ValPtr to_val(const hilti::rt::DeferredExpression<T>& t, ::zeek::TypePtr target,
                             const std::string& location) {
    try {
        return to_val(t(), target, location);
    } catch ( const hilti::rt::AttributeNotSet& ) {
        return nullptr;
    }
}

/**
 * Converts a Spicy-side string to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const std::string& s, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_STRING )
        throw TypeMismatch("string", target, location);

    return ::zeek::make_intrusive<::zeek::StringVal>(s);
}

/**
 * Converts a Spicy-side bytes instance to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Bytes& b, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_STRING )
        throw TypeMismatch("string", target, location);

    return ::zeek::make_intrusive<::zeek::StringVal>(b.str());
}

/**
 * Converts a Spicy-side integer to a Zeek value. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(hilti::rt::integer::safe<T> i, ::zeek::TypePtr target, const std::string& location) {
    ::zeek::ValPtr v = nullptr;
    if constexpr ( std::is_unsigned<T>::value ) {
        if ( target->Tag() == ::zeek::TYPE_COUNT )
            return ::zeek::val_mgr->Count(i);

        if ( target->Tag() == ::zeek::TYPE_INT )
            return ::zeek::val_mgr->Int(i);

        throw TypeMismatch("uint64", target, location);
    }
    else {
        if ( target->Tag() == ::zeek::TYPE_INT )
            return ::zeek::val_mgr->Int(i);

        if ( target->Tag() == ::zeek::TYPE_COUNT ) {
            if ( i >= 0 )
                return ::zeek::val_mgr->Count(i);
            else
                throw TypeMismatch("negative int64", target, location);
        }

        throw TypeMismatch("int64", target, location);
    }
}

template<typename T>
::zeek::ValPtr to_val(const hilti::rt::ValueReference<T>& t, ::zeek::TypePtr target, const std::string& location) {
    if ( auto* x = t.get() )
        return to_val(*x, target, location);

    return nullptr;
}

/**
 * Converts a Spicy-side signed bool to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Bool& b, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_BOOL )
        throw TypeMismatch("bool", target, location);

    return ::zeek::val_mgr->Bool(b);
}

/**
 * Converts a Spicy-side real to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(double r, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_DOUBLE )
        throw TypeMismatch("double", target, location);

    return ::zeek::make_intrusive<::zeek::DoubleVal>(r);
}

/**
 * Converts a Spicy-side address to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Address& d, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_ADDR )
        throw TypeMismatch("addr", target, location);

    auto in_addr = d.asInAddr();
    if ( auto v4 = std::get_if<struct in_addr>(&in_addr) )
        return ::zeek::make_intrusive<::zeek::AddrVal>(::zeek::IPAddr(*v4));
    else {
        auto v6 = std::get<struct in6_addr>(in_addr);
        return ::zeek::make_intrusive<::zeek::AddrVal>(::zeek::IPAddr(v6));
    }
}

/**
 * Converts a Spicy-side address to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Port& p, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_PORT )
        throw TypeMismatch("port", target, location);

    switch ( p.protocol() ) {
        case hilti::rt::Protocol::TCP: return ::zeek::val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_TCP);

        case hilti::rt::Protocol::UDP: return ::zeek::val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_UDP);

        case hilti::rt::Protocol::ICMP: return ::zeek::val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_ICMP);

        default: throw InvalidValue("port value with undefined protocol", location);
    }
}

/**
 * Converts a Spicy-side time to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Interval& i, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_INTERVAL )
        throw TypeMismatch("interval", target, location);

    return ::zeek::make_intrusive<::zeek::IntervalVal>(i.seconds());
}

/**
 * Converts a Spicy-side time to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Time& t, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_TIME )
        throw TypeMismatch("time", target, location);

    return ::zeek::make_intrusive<::zeek::TimeVal>(t.seconds());
}

/**
 * Converts a Spicy-side vector to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(const hilti::rt::Vector<T>& v, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_VECTOR && target->Tag() != ::zeek::TYPE_LIST )
        throw TypeMismatch("expected vector or list", target, location);

    auto vt = ::zeek::cast_intrusive<::zeek::VectorType>(target);
    auto zv = ::zeek::make_intrusive<::zeek::VectorVal>(vt);
    for ( const auto& i : v )
        zv->Assign(zv->Size(), to_val(i, vt->Yield(), location));

    return zv;
}

/**
 * Converts a Spicy-side map to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename K, typename V>
inline ::zeek::ValPtr to_val(const hilti::rt::Map<K, V>& m, ::zeek::TypePtr target, const std::string& location) {
    if constexpr ( hilti::rt::is_tuple<K>::value )
        throw TypeMismatch("internal error: sets with tuples not yet supported in to_val()");

    if ( target->Tag() != ::zeek::TYPE_TABLE )
        throw TypeMismatch("map", target, location);

    auto tt = ::zeek::cast_intrusive<::zeek::TableType>(target);
    if ( tt->IsSet() )
        throw TypeMismatch("map", target, location);

    if ( tt->GetIndexTypes().size() != 1 )
        throw TypeMismatch("map with non-tuple elements", target, location);

    auto zv = ::zeek::make_intrusive<::zeek::TableVal>(tt);

    for ( const auto& i : m ) {
        auto k = to_val(i.first, tt->GetIndexTypes()[0], location);
        auto v = to_val(i.second, tt->Yield(), location);
        zv->Assign(std::move(k), std::move(v));
    }

    return zv;
} // namespace spicy::zeek::rt

/**
 * Converts a Spicy-side set to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(const hilti::rt::Set<T>& s, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_TABLE )
        throw TypeMismatch("set", target, location);

    auto tt = ::zeek::cast_intrusive<::zeek::TableType>(target);
    if ( ! tt->IsSet() )
        throw TypeMismatch("set", target, location);

    auto zv = ::zeek::make_intrusive<::zeek::TableVal>(tt);

    for ( const auto& i : s ) {
        if constexpr ( hilti::rt::is_tuple<T>::value )
            throw TypeMismatch("internal error: sets with tuples not yet supported in to_val()");
        else {
            if ( tt->GetIndexTypes().size() != 1 )
                throw TypeMismatch("set with non-tuple elements", target, location);

            auto idx = to_val(i, tt->GetIndexTypes()[0], location);
            zv->Assign(std::move(idx), nullptr);
        }
    }

    return zv;
}

/**
 * Converts a Spicy-side tuple to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>*>
inline ::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_RECORD )
        throw TypeMismatch("tuple", target, location);

    auto rtype = ::zeek::cast_intrusive<::zeek::RecordType>(target);

    if ( std::tuple_size<T>::value != rtype->NumFields() )
        throw TypeMismatch("tuple", target, location);

    auto rval = ::zeek::make_intrusive<::zeek::RecordVal>(rtype);
    int idx = 0;
    hilti::rt::tuple_for_each(t, [&](const auto& x) {
        ::zeek::ValPtr v = nullptr;

        if constexpr ( std::is_same<decltype(x), const hilti::rt::Null&>::value ) {
            // "Null" turns into an unset optional record field.
        }
        else
            // This may return a nullptr in cases where the field is to be left unset.
            v = to_val(x, rtype->GetFieldType(idx), location);

        if ( v )
            rval->Assign(idx, v);
        else {
            // Field must be &optional or &default.
            if ( auto attrs = rtype->FieldDecl(idx)->attrs; ! attrs || ! (attrs->Find(::zeek::detail::ATTR_DEFAULT) ||
                                                                          attrs->Find(::zeek::detail::ATTR_OPTIONAL)) )
                throw TypeMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx)),
                                   location);
        }

        idx++;
    });

    return rval;
}

/**
 * Converts Spicy-side struct to a Zeek record value. The result is returned
 * with a ref count +1.
 */
template<typename T, typename std::enable_if_t<std::is_base_of<::hilti::rt::trait::isStruct, T>::value>*>
inline ::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_RECORD )
        throw TypeMismatch("struct", target, location);

    auto rtype = ::zeek::cast_intrusive<::zeek::RecordType>(target);

    auto rval = ::zeek::make_intrusive<::zeek::RecordVal>(rtype);
    int idx = 0;

    auto num_fields = rtype->NumFields();

    t.__visit([&](const auto& name, const auto& val) {
        if ( idx >= num_fields )
            throw TypeMismatch(hilti::rt::fmt("no matching record field for field '%s'", name), location);

        auto field = rtype->GetFieldType(idx);
        std::string field_name = rtype->FieldName(idx);

        if ( field_name != name )
            throw TypeMismatch(hilti::rt::fmt("mismatch in field name: expected '%s', found '%s'", name, field_name),
                               location);

        ::zeek::ValPtr v = nullptr;

        if constexpr ( std::is_same<decltype(val), const hilti::rt::Null&>::value ) {
            // "Null" turns into an unset optional record field.
        }
        else
            // This may return a nullptr in cases where the field is to be left unset.
            v = to_val(val, field, location);

        if ( v )
            rval->Assign(idx, v);
        else {
            // Field must be &optional or &default.
            if ( auto attrs = rtype->FieldDecl(idx)->attrs; ! attrs || ! (attrs->Find(::zeek::detail::ATTR_DEFAULT) ||
                                                                          attrs->Find(::zeek::detail::ATTR_OPTIONAL)) )
                throw TypeMismatch(hilti::rt::fmt("missing initialization for field '%s'", field_name), location);
        }

        idx++;
    });

    // We already check above that all Spicy-side fields are mapped so we
    // can only hit this if there are uninitialized Zeek-side fields left.
    if ( idx != num_fields )
        throw TypeMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx + 1)),
                           location);

    return rval;
}

/**
 * Converts a Spicy-side enum to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<std::is_enum<T>::value>*>
inline ::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, const std::string& location) {
    if ( target->Tag() != ::zeek::TYPE_ENUM )
        throw TypeMismatch("enum", target, location);

    // We'll usually be getting an int64_t for T, but allow other signed ints
    // as well.
    static_assert(std::is_signed<std::underlying_type_t<T>>{});
    auto it = static_cast<int64_t>(t);

    // Zeek's enum can't be negative, so we swap in max_int for our Undef (-1).
    if ( it == std::numeric_limits<int64_t>::max() )
        // can't allow this ...
        throw InvalidValue("enum values with value max_int not supported by Zeek integration", location);

    zeek_int_t bt = (it >= 0 ? it : std::numeric_limits<::zeek_int_t>::max());

    return target->AsEnumType()->GetEnumVal(bt);
}

} // namespace spicy::zeek::rt
