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
#include <zeek-spicy/file-analyzer.h>
#include <zeek-spicy/packet-analyzer.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/protocol-analyzer.h>
#include <zeek-spicy/zeek-compat.h>
#include <zeek-spicy/zeek-reporter.h>

#ifdef ZEEK_SPICY_PLUGIN_USE_JIT
namespace spicy::zeek::debug {
const hilti::logging::DebugStream ZeekPlugin("zeek");
}
#endif

plugin::Zeek_Spicy::Plugin SpicyPlugin;
plugin::Zeek_Spicy::Plugin* ::plugin::Zeek_Spicy::OurPlugin = &SpicyPlugin;

using namespace spicy::zeek;

plugin::Zeek_Spicy::Plugin::Plugin() {
    if ( spicy::zeek::configuration::ZeekVersionNumber != ZEEK_VERSION_NUMBER )
        reporter::fatalError(
            hilti::rt::fmt("Zeek version mismatch: running with Zeek %d, but plugin compiled for Zeek %s",
                           ZEEK_VERSION_NUMBER, spicy::zeek::configuration::ZeekVersionNumber));

#ifdef ZEEK_SPICY_PLUGIN_USE_JIT
    hilti::rt::filesystem::path plugin_path;
    std::string name;

#ifdef ZEEK_SPICY_PLUGIN_INTERNAL_BUILD
    auto zeek = hilti::util::currentExecutable();
    auto build_path = zeek.parent_path() / "builtin-plugins" / spicy::zeek::configuration::StaticBuildName;

    if ( hilti::rt::filesystem::exists(build_path) )
        // Running out of build directory. Note that the path below
        // "builtin-plugins/" depends on the directory name where the
        // spicy-plugin code resaides.
        plugin_path = build_path;
    else
        // Installation otherwise.
        plugin_path = zeek.parent_path().parent_path() / spicy::zeek::configuration::InstallLibDir / "zeek-spicy";

    name = zeek.native();
#else
    Dl_info info;
    if ( ! dladdr(&SpicyPlugin, &info) )
        reporter::fatalError("Spicy plugin cannot determine its file system path");

    plugin_path = hilti::rt::filesystem::path(info.dli_fname).parent_path().parent_path();
    name = info.dli_fname;
#endif

    _driver = std::make_unique<Driver>(name.c_str(), plugin_path, spicy::zeek::configuration::ZeekVersionNumber);
#endif
}

void ::spicy::zeek::debug::do_log(const std::string& msg) {
    PLUGIN_DBG_LOG(*plugin::Zeek_Spicy::OurPlugin, "%s", msg.c_str());
    HILTI_RT_DEBUG("zeek", msg);
#ifdef ZEEK_SPICY_PLUGIN_USE_JIT
    HILTI_DEBUG(::spicy::zeek::debug::ZeekPlugin, msg);
#endif
}

plugin::Zeek_Spicy::Plugin::~Plugin() {}

void plugin::Zeek_Spicy::Plugin::addLibraryPaths(const std::string& dirs) {
    for ( const auto& dir : hilti::rt::split(dirs, ":") )
        ::zeek::util::detail::add_to_zeek_path(std::string(dir)); // Add to Zeek's search path.

#ifdef ZEEK_SPICY_PLUGIN_USE_JIT
    _driver->addLibraryPaths(dirs);
#endif
}

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
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", name);
    info.protocol = proto;
    info.ports = ports;
    info.linker_scope = linker_scope;

    if ( replaces.size() ) {
        if ( auto tag = ::zeek::analyzer_mgr->GetAnalyzerTag(replaces.c_str()) ) {
            ZEEK_DEBUG(hilti::rt::fmt("  Replaces existing protocol analyzer %s", replaces));
            info.replaces = tag;
            ::zeek::analyzer_mgr->DisableAnalyzer(tag);
        }
        else
            ZEEK_DEBUG(hilti::rt::fmt("%s i supposed to replace %s, but that does not exist", name, replaces, name));
    }

    ::zeek::analyzer::Component::factory_callback factory = nullptr;

    switch ( proto ) {
        case hilti::rt::Protocol::TCP: factory = spicy::zeek::rt::TCP_Analyzer::InstantiateAnalyzer; break;
        case hilti::rt::Protocol::UDP: factory = spicy::zeek::rt::UDP_Analyzer::InstantiateAnalyzer; break;
        default: reporter::error("unsupported protocol in analyzer"); return;
    }

    auto c = new ::zeek::analyzer::Component(info.name_analyzer, factory, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

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
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", name);
    info.mime_types = mime_types;
    info.linker_scope = linker_scope;

#if ZEEK_VERSION_NUMBER >= 40100
    // Zeek does not have a way to disable file analyzers until 4.1.
    // There's separate logic to nicely reject 'replaces' usages found
    // in .evt files if using inadequate Zeek version, but this is just
    // to make Spicy compilation work regardless.
    if ( replaces.size() ) {
        if ( auto component = ::zeek::file_mgr->Lookup(replaces) ) {
            ZEEK_DEBUG(hilti::rt::fmt("  Replaces existing file analyzer %s", replaces));
            info.replaces = component->Tag();
            component->SetEnabled(false);
        }
        else
            ZEEK_DEBUG(hilti::rt::fmt("%s i supposed to replace %s, but that does not exist", name, replaces, name));
    }
#endif

    auto c = new ::zeek::file_analysis::Component(info.name_analyzer,
                                                  ::spicy::zeek::rt::FileAnalyzer::InstantiateAnalyzer, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

    info.type = c->Tag().Type();
    _file_analyzers_by_type.resize(info.type + 1);
    _file_analyzers_by_type[info.type] = info;
}

void plugin::Zeek_Spicy::Plugin::registerPacketAnalyzer(const std::string& name, const std::string& parser,
                                                        const std::string& linker_scope) {
    ZEEK_DEBUG(hilti::rt::fmt("Have Spicy packet analyzer %s", name));

    PacketAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser = parser;
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", name);
    info.linker_scope = linker_scope;

    auto instantiate = [info]() -> ::zeek::packet_analysis::AnalyzerPtr {
        return ::spicy::zeek::rt::PacketAnalyzer::Instantiate(info.name_analyzer);
    };

    auto c = new ::zeek::packet_analysis::Component(info.name_analyzer, instantiate, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

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
            lval = std::numeric_limits<::bro_int_t>::max();

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

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForProtocolAnalyzer(
    const ::spicy::zeek::compat::AnalyzerTag& tag, bool is_orig) {
    if ( is_orig )
        return _protocol_analyzers_by_type[tag.Type()].parser_orig;
    else
        return _protocol_analyzers_by_type[tag.Type()].parser_resp;
}

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForFileAnalyzer(
    const ::spicy::zeek::compat::FileAnalysisTag& tag) {
    return _file_analyzers_by_type[tag.Type()].parser;
}

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForPacketAnalyzer(
    const ::spicy::zeek::compat::PacketAnalysisTag& tag) {
    return _packet_analyzers_by_type[tag.Type()].parser;
}

::spicy::zeek::compat::AnalyzerTag plugin::Zeek_Spicy::Plugin::tagForProtocolAnalyzer(
    const ::spicy::zeek::compat::AnalyzerTag& tag) {
    if ( auto r = _protocol_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

::spicy::zeek::compat::FileAnalysisTag plugin::Zeek_Spicy::Plugin::tagForFileAnalyzer(
    const ::spicy::zeek::compat::FileAnalysisTag& tag) {
    if ( auto r = _file_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

::spicy::zeek::compat::AnalyzerTag plugin::Zeek_Spicy::Plugin::tagForPacketAnalyzer(
    const ::spicy::zeek::compat::AnalyzerTag& tag) {
    // Don't have a replacement mechanism currently.
    return tag;
}

bool plugin::Zeek_Spicy::Plugin::toggleProtocolAnalyzer(const ::spicy::zeek::compat::AnalyzerTag& tag, bool enable) {
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

bool plugin::Zeek_Spicy::Plugin::toggleFileAnalyzer(const ::spicy::zeek::compat::FileAnalysisTag& tag, bool enable) {
    auto type = tag.Type();

    if ( type >= _file_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _file_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;

#if ZEEK_VERSION_NUMBER >= 40100
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
#else
    ZEEK_DEBUG(hilti::rt::fmt("supposed to toggle file analyzer %s, but that is not supported by Zeek version",
                              analyzer.name_analyzer));
    return false;
#endif
}

bool plugin::Zeek_Spicy::Plugin::togglePacketAnalyzer(const ::spicy::zeek::compat::PacketAnalysisTag& tag,
                                                      bool enable) {
    auto type = tag.Type();

    if ( type >= _packet_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _protocol_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;
    ZEEK_DEBUG(hilti::rt::fmt("supposed to toggle packet analyzer %s, but that is not supported by Zeek",
                              analyzer.name_analyzer));
    return false;
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
    config.description = "Support for Spicy parsers (*.spicy, *.evt, *.hlto)";
    config.version.major = spicy::zeek::configuration::PluginVersionMajor;
    config.version.minor = spicy::zeek::configuration::PluginVersionMinor;
    config.version.patch = spicy::zeek::configuration::PluginVersionPatch;

    EnableHook(::zeek::plugin::HOOK_LOAD_FILE);

    return config;
}

void plugin::Zeek_Spicy::Plugin::InitPreScript() {
    zeek::plugin::Plugin::InitPreScript();

    ZEEK_DEBUG("Beginning pre-script initialization");

#ifdef ZEEK_SPICY_PLUGIN_USE_JIT
    _driver->InitPreScript();
#endif

    // Note that, different from Spicy's own SPICY_PATH, this extends the
    // search path, it doesn't replace it.
    if ( auto dir = hilti::rt::getenv("ZEEK_SPICY_PATH") )
        addLibraryPaths(*dir);

    addLibraryPaths(hilti::rt::normalizePath(OurPlugin->PluginDirectory()).string() + "/spicy");
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
    switch ( port.protocol() ) {
        case hilti::rt::Protocol::TCP: return ::TransportProto::TRANSPORT_TCP;
        case hilti::rt::Protocol::UDP: return ::TransportProto::TRANSPORT_UDP;
        case hilti::rt::Protocol::ICMP: return ::TransportProto::TRANSPORT_ICMP;
        default:
            reporter::internalError(
                hilti::rt::fmt("unsupported transport protocol in port '%s' for Zeek conversion", port));
            return ::TransportProto::TRANSPORT_UNKNOWN;
    }
}

void plugin::Zeek_Spicy::Plugin::InitPostScript() {
    zeek::plugin::Plugin::InitPostScript();

    ZEEK_DEBUG("Beginning post-script initialization");

#ifdef ZEEK_SPICY_PLUGIN_USE_JIT
    _driver->InitPostScript();
#endif

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

    auto config = hilti::rt::configuration::get();

    if ( ::zeek::id::find_const("Spicy::enable_print")->AsBool() ) //NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
        config.cout = std::cout;
    else
        config.cout.reset();

    config.abort_on_exceptions = ::zeek::id::find_const("Spicy::abort_on_exceptions")->AsBool();
    config.show_backtraces = ::zeek::id::find_const("Spicy::show_backtraces")->AsBool();

    hilti::rt::configuration::set(config);

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
        auto tag = ::zeek::analyzer_mgr->GetAnalyzerTag(p.name_analyzer.c_str());
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
        auto tag = ::zeek::file_mgr->GetComponentTag(p.name_analyzer.c_str());
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
    } catch ( const hilti::rt::EnvironmentError& e ) {
        hilti::rt::fatalError(e.what());
    }
}

int plugin::Zeek_Spicy::Plugin::HookLoadFile(const LoadType type, const std::string& file,
                                             const std::string& resolved) {
#ifdef ZEEK_SPICY_PLUGIN_USE_JIT
    if ( int rc = _driver->HookLoadFile(type, file, resolved) >= 0 )
        return rc;
#endif

    auto ext = hilti::rt::filesystem::path(file).extension();

    if ( ext == ".hlto" ) {
        loadModule(file);
        return 1;
    }

    if ( ext == ".spicy" || ext == ".evt" || ext == ".hlt" )
        reporter::fatalError(hilti::rt::fmt("cannot load '%s', Spicy plugin was not compiled with JIT support", file));

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
