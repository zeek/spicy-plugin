// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>
#include <glob.h>

#include <exception>

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/configuration.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/init.h>
#include <hilti/rt/library.h>
#include <hilti/rt/types/vector.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>

#include <hilti/autogen/config.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/plugin/file-analyzer.h>
#include <zeek-spicy/plugin/packet-analyzer.h>
#include <zeek-spicy/plugin/plugin.h>
#include <zeek-spicy/plugin/protocol-analyzer.h>
#include <zeek-spicy/plugin/zeek-compat.h>
#include <zeek-spicy/plugin/zeek-reporter.h>

const char* ZEEK_SPICY_PLUGIN_VERSION_FUNCTION() { return spicy::zeek::configuration::PluginVersion; }

plugin::Zeek_Spicy::Plugin SpicyPlugin;
plugin::Zeek_Spicy::Plugin* ::plugin::Zeek_Spicy::OurPlugin = &SpicyPlugin;

using namespace spicy::zeek;

plugin::Zeek_Spicy::Plugin::Plugin() {
#ifdef HILTI_VERSION_FUNCTION
    // This ensures version compatibility at dlopen() time  by requiring the
    // versioned symbol to be present. The symbol is available starting with
    // Spicy 1.6.
    _spicy_version = HILTI_VERSION_FUNCTION();
#endif

    // Not sure if with the with the check above, we still need this? Can't hurt I guess.
    if ( spicy::zeek::configuration::ZeekVersionNumber != ZEEK_VERSION_NUMBER )
        reporter::fatalError(
            hilti::rt::fmt("Zeek version mismatch: running with Zeek %d, but plugin compiled for Zeek %s",
                           ZEEK_VERSION_NUMBER, spicy::zeek::configuration::ZeekVersionNumber));
}

void ::spicy::zeek::debug::do_log(const std::string& msg) {
    PLUGIN_DBG_LOG(*plugin::Zeek_Spicy::OurPlugin, "%s", msg.c_str());
    HILTI_RT_DEBUG("zeek", msg);
}

plugin::Zeek_Spicy::Plugin::~Plugin() {}

void plugin::Zeek_Spicy::Plugin::registerProtocolAnalyzer(const std::string& name, hilti::rt::Protocol proto,
                                                          const hilti::rt::Vector<hilti::rt::Port>& ports,
                                                          const std::string& parser_orig,
                                                          const std::string& parser_resp, const std::string& replaces,
                                                          const std::string& linker_scope) {
    ZEEK_DEBUG(hilti::rt::fmt("Have Spicy protocol analyzer %s", name));

    ProtocolAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser_orig = parser_orig;
    info.name_parser_resp = parser_resp;
    info.name_replaces = replaces;
    info.name_zeek = hilti::util::replace(name, "::", "_");
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", name);
    info.protocol = proto;
    info.ports = ports;
    info.linker_scope = linker_scope;

    // We may have that analyzer already iff it was previously pre-registered
    // without a linker scope. We'll then only set the scope now.
    if ( auto c = findComponent(info.name_zeek) ) {
        ZEEK_DEBUG(hilti::rt::fmt("Updating already registered protocol analyzer %s", name));

        const auto& tag = _analyzer_name_to_tag_type.at(c->Name());
        auto& existing = _protocol_analyzers_by_type.at(tag);
        assert(existing.name_analyzer == name);
        existing.linker_scope = info.linker_scope;

        // If the infos don't match now, we have two separate definitions.
        if ( info != existing )
            reporter::fatalError(hilti::rt::fmt("redefinition of protocol analyzer %s", info.name_analyzer));

        return;
    }

    ::zeek::analyzer::Component::factory_callback factory = nullptr;

#if SPICY_VERSION_NUMBER >= 10700
    auto proto_ = proto.value();
#else
    auto proto_ = proto;
#endif

    switch ( proto_ ) {
        case hilti::rt::Protocol::TCP: factory = spicy::zeek::rt::TCP_Analyzer::InstantiateAnalyzer; break;
        case hilti::rt::Protocol::UDP: factory = spicy::zeek::rt::UDP_Analyzer::InstantiateAnalyzer; break;
        default: reporter::error("unsupported protocol in analyzer"); return;
    }

    auto c = new ::zeek::analyzer::Component(info.name_zeek, factory, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

    trackComponent(c, c->Tag().Type()); // Must come after Initialize().

    info.type = c->Tag().Type();
    _protocol_analyzers_by_type.resize(info.type + 1);
    _protocol_analyzers_by_type[info.type] = info;
}

void plugin::Zeek_Spicy::Plugin::registerFileAnalyzer(const std::string& name,
                                                      const hilti::rt::Vector<std::string>& mime_types,
                                                      const std::string& parser, const std::string& replaces,
                                                      const std::string& linker_scope) {
    ZEEK_DEBUG(hilti::rt::fmt("Have Spicy file analyzer %s", name));

    FileAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser = parser;
    info.name_replaces = replaces;
    info.name_zeek = hilti::util::replace(name, "::", "_");
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", name);
    info.mime_types = mime_types;
    info.linker_scope = linker_scope;

    // We may have that analyzer already iff it was previously pre-registered
    // without a linker scope. We'll then only set the scope now.
    if ( auto c = findComponent(info.name_zeek) ) {
        ZEEK_DEBUG(hilti::rt::fmt("Updating already registered packet analyzer %s", name));

        const auto& tag = _analyzer_name_to_tag_type.at(c->Name());
        auto& existing = _file_analyzers_by_type.at(tag);
        existing.linker_scope = info.linker_scope;

        // If the infos don't match now, we have two separate definitions.
        if ( info != existing )
            reporter::fatalError(hilti::rt::fmt("redefinition of file analyzer %s", info.name_analyzer));

        return;
    }

    auto c =
        new ::zeek::file_analysis::Component(info.name_zeek, ::spicy::zeek::rt::FileAnalyzer::InstantiateAnalyzer, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

    trackComponent(c, c->Tag().Type()); // Must come after Initialize().

    info.type = c->Tag().Type();
    _file_analyzers_by_type.resize(info.type + 1);
    _file_analyzers_by_type[info.type] = info;
}

void plugin::Zeek_Spicy::Plugin::registerPacketAnalyzer(const std::string& name, const std::string& parser,
                                                        const std::string& replaces, const std::string& linker_scope) {
    ZEEK_DEBUG(hilti::rt::fmt("Have Spicy packet analyzer %s", name));

    PacketAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_replaces = replaces;
    info.name_parser = parser;
    info.name_zeek = hilti::util::replace(name, "::", "_");
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", info.name_zeek);
    info.linker_scope = linker_scope;

    // We may have that analyzer already iff it was previously pre-registered
    // without a linker scope. We'll then set the scope now.
    if ( auto c = findComponent(info.name_zeek) ) {
        ZEEK_DEBUG(hilti::rt::fmt("Updating already registered packet analyzer %s", name));

        const auto& tag = _analyzer_name_to_tag_type.at(c->Name());
        auto& existing = _packet_analyzers_by_type.at(tag);
        assert(existing.name_analyzer == name);
        existing.linker_scope = info.linker_scope;

        // If the infos don't match now, we have two separate definitions.
        if ( info != existing )
            reporter::fatalError(hilti::rt::fmt("redefinition of packet analyzer %s", info.name_analyzer));

        return;
    }

    auto instantiate = [info]() -> ::zeek::packet_analysis::AnalyzerPtr {
        return ::spicy::zeek::rt::PacketAnalyzer::Instantiate(info.name_zeek);
    };

    auto c = new ::zeek::packet_analysis::Component(info.name_zeek, instantiate, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

    trackComponent(c, c->Tag().Type()); // Must come after Initialize().

    info.type = c->Tag().Type();
    _packet_analyzers_by_type.resize(info.type + 1);
    _packet_analyzers_by_type[info.type] = info;
}

void plugin::Zeek_Spicy::Plugin::registerEnumType(
    const std::string& ns, const std::string& id,
    const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels) {
    if ( ::zeek::detail::lookup_ID(id.c_str(), ns.c_str()) )
        // Already exists, which means it's either done by the Spicy plugin
        // already, or provided manually. We leave it alone then.
        return;

    auto fqid = hilti::rt::fmt("%s::%s", ns, id);
    ZEEK_DEBUG(hilti::rt::fmt("Adding Zeek enum type %s", fqid));

    auto etype = ::zeek::make_intrusive<::zeek::EnumType>(fqid);

    for ( auto [lid, lval] : labels ) {
        auto name = ::hilti::rt::fmt("%s_%s", id, lid);

        if ( lval == -1 )
            // Zeek's enum can't be negative, so swap int max_int for our Undef.
            lval = std::numeric_limits<::zeek_int_t>::max();

        etype->AddName(ns, name.c_str(), lval, true);
    }

    auto zeek_id = ::zeek::detail::install_ID(id.c_str(), ns.c_str(), true, true);
    zeek_id->SetType(etype);
    zeek_id->MakeType();
}

void plugin::Zeek_Spicy::Plugin::registerEvent(const std::string& name) {
    // Create a Zeek handler for the event.
    ::zeek::event_registry->Register(name);

    // Install the ID into the corresponding namespace and export it.
    auto n = ::hilti::rt::split(name, "::");
    std::string mod;

    if ( n.size() > 1 )
        mod = n.front();
    else
        mod = ::zeek::detail::GLOBAL_MODULE_NAME;

    if ( auto id = ::zeek::detail::lookup_ID(name.c_str(), mod.c_str(), false, false, false) ) {
        // Auto-export IDs that already exist.
        id->SetExport();
        _events[name] = id;
    }
    else
        // This installs & exports the ID, but it doesn't set its type yet.
        // That will happen as handlers get defined. If there are no hanlders,
        // we set a dummy type in the plugin's InitPostScript
        _events[name] = ::zeek::detail::install_ID(name.c_str(), mod.c_str(), false, true);
}

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForProtocolAnalyzer(const ::zeek::Tag& tag, bool is_orig) {
    if ( is_orig )
        return _protocol_analyzers_by_type[tag.Type()].parser_orig;
    else
        return _protocol_analyzers_by_type[tag.Type()].parser_resp;
}

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForFileAnalyzer(const ::zeek::Tag& tag) {
    return _file_analyzers_by_type[tag.Type()].parser;
}

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForPacketAnalyzer(const ::zeek::Tag& tag) {
    return _packet_analyzers_by_type[tag.Type()].parser;
}

::zeek::Tag plugin::Zeek_Spicy::Plugin::tagForProtocolAnalyzer(const ::zeek::Tag& tag) {
    if ( auto r = _protocol_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

::zeek::Tag plugin::Zeek_Spicy::Plugin::tagForFileAnalyzer(const ::zeek::Tag& tag) {
    if ( auto r = _file_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

::zeek::Tag plugin::Zeek_Spicy::Plugin::tagForPacketAnalyzer(const ::zeek::Tag& tag) {
    if ( auto r = _packet_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

bool plugin::Zeek_Spicy::Plugin::toggleProtocolAnalyzer(const ::zeek::Tag& tag, bool enable) {
    auto type = tag.Type();

    if ( type >= _protocol_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _protocol_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;

    if ( enable ) {
        ZEEK_DEBUG(hilti::rt::fmt("Enabling Spicy protocol analyzer %s", analyzer.name_analyzer));
        ::zeek::analyzer_mgr->EnableAnalyzer(tag);

        if ( analyzer.replaces ) {
            ZEEK_DEBUG(hilti::rt::fmt("Disabling standard protocol analyzer %s", analyzer.name_analyzer));
            ::zeek::analyzer_mgr->DisableAnalyzer(analyzer.replaces);
        }
    }
    else {
        ZEEK_DEBUG(hilti::rt::fmt("Disabling Spicy protocol analyzer %s", analyzer.name_analyzer));
        ::zeek::analyzer_mgr->DisableAnalyzer(tag);

        if ( analyzer.replaces ) {
            ZEEK_DEBUG(hilti::rt::fmt("Re-enabling standard protocol analyzer %s", analyzer.name_analyzer));
            ::zeek::analyzer_mgr->EnableAnalyzer(analyzer.replaces);
        }
    }

    return true;
}

bool plugin::Zeek_Spicy::Plugin::toggleFileAnalyzer(const ::zeek::Tag& tag, bool enable) {
    auto type = tag.Type();

    if ( type >= _file_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _file_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;

    ::zeek::file_analysis::Component* component = ::zeek::file_mgr->Lookup(tag);
    ::zeek::file_analysis::Component* component_replaces =
        analyzer.replaces ? ::zeek::file_mgr->Lookup(analyzer.replaces) : nullptr;

    if ( ! component ) {
        // Shouldn't really happen.
        reporter::internalError("failed to lookup file analyzer component");
        return false;
    }

    if ( enable ) {
        ZEEK_DEBUG(hilti::rt::fmt("Enabling Spicy file analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(true);

        if ( component_replaces ) {
            ZEEK_DEBUG(hilti::rt::fmt("Disabling standard file analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(false);
        }
    }
    else {
        ZEEK_DEBUG(hilti::rt::fmt("Disabling Spicy file analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(false);

        if ( component_replaces ) {
            ZEEK_DEBUG(hilti::rt::fmt("Enabling standard file analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(true);
        }
    }

    return true;
}

bool plugin::Zeek_Spicy::Plugin::togglePacketAnalyzer(const ::zeek::Tag& tag, bool enable) {
    auto type = tag.Type();

    if ( type >= _packet_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _packet_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;

#if ZEEK_VERSION_NUMBER >= 50200
    ::zeek::packet_analysis::Component* component = ::zeek::packet_mgr->Lookup(tag);
    ::zeek::packet_analysis::Component* component_replaces =
        analyzer.replaces ? ::zeek::packet_mgr->Lookup(analyzer.replaces) : nullptr;

    if ( ! component ) {
        // Shouldn't really happen.
        reporter::internalError("failed to lookup packet analyzer component");
        return false;
    }

    if ( enable ) {
        ZEEK_DEBUG(hilti::rt::fmt("Enabling Spicy packet analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(true);

        if ( component_replaces ) {
            ZEEK_DEBUG(hilti::rt::fmt("Disabling standard packet analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(false);
        }
    }
    else {
        ZEEK_DEBUG(hilti::rt::fmt("Disabling Spicy packet analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(false);

        if ( component_replaces ) {
            ZEEK_DEBUG(hilti::rt::fmt("Enabling standard packet analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(true);
        }
    }

    return true;
#else
    ZEEK_DEBUG(hilti::rt::fmt("supposed to toggle packet analyzer %s, but that is not supported by Zeek version",
                              analyzer.name_analyzer));
    return false;
#endif
}

bool plugin::Zeek_Spicy::Plugin::toggleAnalyzer(::zeek::EnumVal* tag, bool enable) {
    if ( tag->GetType() == ::zeek::analyzer_mgr->GetTagType() ) {
        if ( auto analyzer = ::zeek::analyzer_mgr->Lookup(tag) )
            return toggleProtocolAnalyzer(analyzer->Tag(), enable);
        else
            return false;
    }

    if ( tag->GetType() == ::zeek::file_mgr->GetTagType() ) {
        if ( auto analyzer = ::zeek::file_mgr->Lookup(tag) )
            return toggleFileAnalyzer(analyzer->Tag(), enable);
        else
            return false;
    }

    if ( tag->GetType() == ::zeek::packet_mgr->GetTagType() ) {
        if ( auto analyzer = ::zeek::packet_mgr->Lookup(tag) )
            return togglePacketAnalyzer(analyzer->Tag(), enable);
        else
            return false;
    }

    return false;
}

::zeek::plugin::Configuration plugin::Zeek_Spicy::Plugin::Configure() {
    ::zeek::plugin::Configuration config;
    config.name = "Zeek::Spicy";
    config.description = "Support for Spicy parsers (``*.hlto``)";
    config.version.major = spicy::zeek::configuration::PluginVersionMajor;
    config.version.minor = spicy::zeek::configuration::PluginVersionMinor;
    config.version.patch = spicy::zeek::configuration::PluginVersionPatch;

    EnableHook(::zeek::plugin::HOOK_LOAD_FILE);

    return config;
}

void plugin::Zeek_Spicy::Plugin::InitPreScript() {
    zeek::plugin::Plugin::InitPreScript();

    ZEEK_DEBUG("Beginning pre-script initialization");

    hilti::rt::executeManualPreInits();

    autoDiscoverModules();

    if ( strlen(spicy::zeek::configuration::PluginScriptsDirectory) &&
         ! hilti::rt::getenv(
             "ZEEKPATH") ) { // similar to Zeek: don't touch ZEEKPATH if set to anything (including empty)
        ZEEK_DEBUG(hilti::rt::fmt("Adding %s to ZEEKPATH", spicy::zeek::configuration::PluginScriptsDirectory));
        ::zeek::util::detail::add_to_zeek_path(spicy::zeek::configuration::PluginScriptsDirectory);
    }

    ZEEK_DEBUG("Done with pre-script initialization");
}

// Returns a port's Zeek-side transport protocol.
static ::TransportProto transport_protocol(const hilti::rt::Port port) {
#if SPICY_VERSION_NUMBER >= 10700
    auto proto = port.protocol().value();
#else
    auto proto = port.protocol();
#endif

    switch ( proto ) {
        case hilti::rt::Protocol::TCP: return ::TransportProto::TRANSPORT_TCP;
        case hilti::rt::Protocol::UDP: return ::TransportProto::TRANSPORT_UDP;
        case hilti::rt::Protocol::ICMP: return ::TransportProto::TRANSPORT_ICMP;
        default:
            reporter::internalError(
                hilti::rt::fmt("unsupported transport protocol in port '%s' for Zeek conversion", port));
            return ::TransportProto::TRANSPORT_UNKNOWN;
    }
}

static void hook_accept_input() {
    auto cookie = static_cast<rt::Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<rt::cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = plugin::Zeek_Spicy::OurPlugin->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        ZEEK_DEBUG(hilti::rt::fmt("confirming protocol %s", tag.AsString()));
        return x->analyzer->AnalyzerConfirmation(tag);
    }
}

static void hook_decline_input(const std::string& reason) {
    auto cookie = static_cast<rt::Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<rt::cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = plugin::Zeek_Spicy::OurPlugin->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        ZEEK_DEBUG(hilti::rt::fmt("rejecting protocol %s", tag.AsString()));
        return x->analyzer->AnalyzerViolation("protocol rejected", nullptr, 0, tag);
    }
}

void plugin::Zeek_Spicy::Plugin::InitPostScript() {
    zeek::plugin::Plugin::InitPostScript();

    ZEEK_DEBUG("Beginning post-script initialization");

    disableReplacedAnalyzers();

    // If there's no handler for one of our events, it won't have received a
    // type. Give it a dummy event type in that case, so that we don't walk
    // around with a nullptr.
    for ( const auto& [name, id] : _events ) {
        if ( ! id->GetType() ) {
            auto args = ::zeek::make_intrusive<::zeek::RecordType>(new ::zeek::type_decl_list());
            auto et = ::zeek::make_intrusive<::zeek::FuncType>(std::move(args), ::zeek::base_type(::zeek::TYPE_VOID),
                                                               ::zeek::FUNC_FLAVOR_EVENT);
            id->SetType(std::move(et));
        }
    }

    // Init runtime, which will trigger all initialization code to execute.
    ZEEK_DEBUG("Initializing Spicy runtime");

    auto hilti_config = hilti::rt::configuration::get();

    if ( ::zeek::id::find_const("Spicy::enable_print")->AsBool() ) //NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
        hilti_config.cout = std::cout;
    else
        hilti_config.cout.reset();

    hilti_config.abort_on_exceptions = ::zeek::id::find_const("Spicy::abort_on_exceptions")->AsBool();
    hilti_config.show_backtraces = ::zeek::id::find_const("Spicy::show_backtraces")->AsBool();

    hilti::rt::configuration::set(hilti_config);

    auto spicy_config = spicy::rt::configuration::get();
    spicy_config.hook_accept_input = hook_accept_input;
    spicy_config.hook_decline_input = hook_decline_input;
    spicy::rt::configuration::set(std::move(spicy_config));

    try {
        hilti::rt::init();
        spicy::rt::init();
    } catch ( const hilti::rt::Exception& e ) {
        std::cerr << hilti::rt::fmt("uncaught runtime exception %s during initialization: %s",
                                    hilti::rt::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    } catch ( const std::runtime_error& e ) {
        std::cerr << hilti::rt::fmt("uncaught C++ exception %s during initialization: %s",
                                    hilti::rt::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    }

    // Fill in the parser information now that we derived from the ASTs.
    auto find_parser = [](const std::string& analyzer, const std::string& parser,
                          const std::string& linker_scope) -> const spicy::rt::Parser* {
        if ( parser.empty() )
            return nullptr;

        for ( auto p : spicy::rt::parsers() ) {
            if ( p->name == parser && p->linker_scope == linker_scope )
                return p;
        }

        reporter::internalError(
            hilti::rt::fmt("Unknown Spicy parser '%s' requested by analyzer '%s'", parser, analyzer));

        return nullptr; // cannot be reached
    };

    for ( auto& p : _protocol_analyzers_by_type ) {
        if ( p.type == 0 )
            // vector element not set
            continue;

        ZEEK_DEBUG(hilti::rt::fmt("Registering %s protocol analyzer %s with Zeek", p.protocol, p.name_analyzer));

        p.parser_orig = find_parser(p.name_analyzer, p.name_parser_orig, p.linker_scope);
        p.parser_resp = find_parser(p.name_analyzer, p.name_parser_resp, p.linker_scope);

        // Register analyzer for its well-known ports.
        auto tag = ::zeek::analyzer_mgr->GetAnalyzerTag(p.name_zeek.c_str());
        if ( ! tag )
            reporter::internalError(hilti::rt::fmt("cannot get analyzer tag for '%s'", p.name_analyzer));

        for ( auto port : p.ports ) {
            ZEEK_DEBUG(hilti::rt::fmt("  Scheduling analyzer for port %s", port));
            ::zeek::analyzer_mgr->RegisterAnalyzerForPort(tag, transport_protocol(port), port.port());
        }

        if ( p.parser_resp ) {
            for ( auto port : p.parser_resp->ports ) {
                if ( port.direction != spicy::rt::Direction::Both && port.direction != spicy::rt::Direction::Responder )
                    continue;

                ZEEK_DEBUG(hilti::rt::fmt("  Scheduling analyzer for port %s", port.port));
                ::zeek::analyzer_mgr->RegisterAnalyzerForPort(tag, transport_protocol(port.port), port.port.port());
            }
        }
    }

    for ( auto& p : _file_analyzers_by_type ) {
        if ( p.type == 0 )
            // vector element not set
            continue;

        ZEEK_DEBUG(hilti::rt::fmt("Registering file analyzer %s with Zeek", p.name_analyzer.c_str()));

        p.parser = find_parser(p.name_analyzer, p.name_parser, p.linker_scope);

        // Register analyzer for its MIME types.
        auto tag = ::zeek::file_mgr->GetComponentTag(p.name_zeek.c_str());
        if ( ! tag )
            reporter::internalError(hilti::rt::fmt("cannot get analyzer tag for '%s'", p.name_analyzer));

        auto register_analyzer_for_mime_type = [&](auto tag, const std::string& mt) {
            ZEEK_DEBUG(hilti::rt::fmt("  Scheduling analyzer for MIME type %s", mt));

            // MIME types are registered in scriptland, so we'll raise an
            // event that will do it for us through a predefined handler.
            zeek::Args vals = ::zeek::Args();
            vals.emplace_back(tag.AsVal());
            vals.emplace_back(::zeek::make_intrusive<::zeek::StringVal>(mt));
            ::zeek::EventHandlerPtr handler = ::zeek::event_registry->Register("spicy_analyzer_for_mime_type");
            ::zeek::event_mgr.Enqueue(handler, vals);
        };

        for ( const auto& mt : p.mime_types )
            register_analyzer_for_mime_type(tag, mt);

        if ( p.parser ) {
            for ( const auto& mt : p.parser->mime_types )
                register_analyzer_for_mime_type(tag, mt);
        }
    }

    for ( auto& p : _packet_analyzers_by_type ) {
        if ( p.type == 0 )
            // vector element not set
            continue;

        ZEEK_DEBUG(hilti::rt::fmt("Registering packet analyzer %s with Zeek", p.name_analyzer.c_str()));
        p.parser = find_parser(p.name_analyzer, p.name_parser, p.linker_scope);
    }

    ZEEK_DEBUG("Done with post-script initialization");
}


void plugin::Zeek_Spicy::Plugin::Done() {
    ZEEK_DEBUG("Shutting down Spicy runtime");
    spicy::rt::done();
    hilti::rt::done();
}

void plugin::Zeek_Spicy::Plugin::loadModule(const hilti::rt::filesystem::path& path) {
    try {
        // If our auto discovery ends up finding the same module multiple times,
        // we ignore subsequent requests.
        auto canonical_path = hilti::rt::filesystem::canonical(path);

        if ( auto [library, inserted] = _libraries.insert({canonical_path, hilti::rt::Library(canonical_path)});
             inserted ) {
            ZEEK_DEBUG(hilti::rt::fmt("Loading %s", canonical_path.native()));
            if ( auto load = library->second.open(); ! load )
                hilti::rt::fatalError(
                    hilti::rt::fmt("could not open library path %s: %s", canonical_path, load.error()));
        }
        else {
            ZEEK_DEBUG(hilti::rt::fmt("Ignoring duplicate loading request for %s", canonical_path.native()));
        }
#if SPICY_VERSION_NUMBER >= 10700
    } catch ( const ::hilti::rt::UsageError& e ) {
#else
    } catch ( const ::hilti::rt::UserException& e ) {
#endif
        hilti::rt::fatalError(e.what());
    }
}

int plugin::Zeek_Spicy::Plugin::HookLoadFile(const LoadType type, const std::string& file,
                                             const std::string& resolved) {
    auto ext = hilti::rt::filesystem::path(file).extension();

    if ( ext == ".hlto" ) {
        loadModule(file);
        return 1;
    }

    if ( ext == ".spicy" || ext == ".evt" || ext == ".hlt" )
        reporter::fatalError(hilti::rt::fmt("cannot load '%s': analyzers need to be precompiled with 'spicyz' ", file));

    return -1;
}

void plugin::Zeek_Spicy::Plugin::searchModules(const std::string& paths) {
    for ( const auto& dir : hilti::rt::split(paths, ":") ) {
        auto trimmed_dir = hilti::rt::trim(dir);
        if ( trimmed_dir.empty() )
            continue;

        if ( ! hilti::rt::filesystem::is_directory(trimmed_dir) ) {
            ZEEK_DEBUG(hilti::rt::fmt("Module directory %s does not exist, skipping", trimmed_dir));
            continue;
        }

        ZEEK_DEBUG(hilti::rt::fmt("Searching %s for *.hlto", trimmed_dir));

        for ( const auto& e : hilti::rt::filesystem::recursive_directory_iterator(trimmed_dir) ) {
            if ( e.is_regular_file() && e.path().extension() == ".hlto" )
                loadModule(e.path());
        }
    }
};

::zeek::detail::Location plugin::Zeek_Spicy::Plugin::makeLocation(const std::string& fname) {
    auto x = _locations.insert(fname);
    return ::zeek::detail::Location(x.first->c_str(), 0, 0, 0, 0);
}

void plugin::Zeek_Spicy::Plugin::autoDiscoverModules() {
    if ( auto search_paths = hilti::rt::getenv("ZEEK_SPICY_MODULE_PATH"); search_paths && search_paths->size() )
        // This overrides all other paths.
        searchModules(*search_paths);
    else {
        searchModules(spicy::zeek::configuration::PluginModuleDirectory);
        searchModules(zeek::util::zeek_plugin_path());
    }
}

void plugin::Zeek_Spicy::Plugin::disableReplacedAnalyzers() {
    for ( auto& info : _protocol_analyzers_by_type ) {
        if ( info.name_replaces.empty() )
            continue;

        auto replaces = info.name_replaces.c_str();

        if ( ::zeek::file_mgr->Lookup(replaces) || ::zeek::packet_mgr->Lookup(replaces) )
            reporter::fatalError(hilti::rt::fmt("cannot replace '%s' analyzer with a protocol analyzer", replaces));

        auto tag = ::zeek::analyzer_mgr->GetAnalyzerTag(replaces);
        if ( ! tag ) {
            ZEEK_DEBUG(hilti::rt::fmt("%s is supposed to replace protocol analyzer %s, but that does not exist",
                                      info.name_analyzer, replaces));

            continue;
        }

        ZEEK_DEBUG(hilti::rt::fmt("%s replaces existing protocol analyzer %s", info.name_analyzer, replaces));
        info.replaces = tag;
        ::zeek::analyzer_mgr->DisableAnalyzer(tag);
    }

    for ( auto& info : _file_analyzers_by_type ) {
        if ( info.name_replaces.empty() )
            continue;

        auto replaces = info.name_replaces.c_str();

        if ( ::zeek::analyzer_mgr->Lookup(replaces) || ::zeek::packet_mgr->Lookup(replaces) )
            reporter::fatalError(hilti::rt::fmt("cannot replace '%s' analyzer with a file analyzer", replaces));

        auto component = ::zeek::file_mgr->Lookup(replaces);
        if ( ! component ) {
            ZEEK_DEBUG(hilti::rt::fmt("%s is supposed to replace file analyzer %s, but that does not exist",
                                      info.name_analyzer, replaces));

            continue;
        }

        ZEEK_DEBUG(hilti::rt::fmt("%s replaces existing file analyzer %s", info.name_analyzer, replaces));
        info.replaces = component->Tag();
        component->SetEnabled(false);
    }

#if ZEEK_VERSION_NUMBER >= 50200
    // Zeek does not have a way to disable packet analyzers until 4.1. There's
    // separate logic to nicely reject 'replaces' usages found in .evt packets
    // if using inadequate Zeek version; this #ifdef is just to make Spicy
    // compilation work regardless.

    for ( auto& info : _packet_analyzers_by_type ) {
        if ( info.name_replaces.empty() )
            continue;

        auto replaces = info.name_replaces.c_str();

        auto component = ::zeek::packet_mgr->Lookup(replaces);
        if ( ! component ) {
            ZEEK_DEBUG(hilti::rt::fmt("%s is supposed to replace packet analyzer %s, but that does not exist",
                                      info.name_analyzer, replaces));

            continue;
        }

        ZEEK_DEBUG(hilti::rt::fmt("%s replaces existing packet analyzer %s", info.name_analyzer, replaces));
        info.replaces = component->Tag();
        component->SetEnabled(false);
    }
#endif
}


void plugin::Zeek_Spicy::Plugin::trackComponent(::zeek::plugin::Component* c, int32_t tag_type) {
    auto i = _analyzer_name_to_tag_type.insert({c->Name(), tag_type});
    if ( ! i.second )
        // We enforce on our end that an analyzer name can appear only once
        // across all types of analyzers. Makes things easier and avoids
        // confusion.
        reporter::fatalError(hilti::rt::fmt("duplicate analyzer name '%s'", c->Name()));
}

const ::zeek::plugin::Component* plugin::Zeek_Spicy::Plugin::findComponent(const std::string& name) {
    for ( const auto& c : Components() ) {
        if ( c->Name() == name )
            return c;
    }

    return nullptr;
}
