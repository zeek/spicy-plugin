// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// Provides backwards compatibility for older Zeek versions.

#pragma once

#include <zeek-spicy/autogen/config.h>

#include <zeek/zeek-config.h>

// When building as internal plugin, the newest Zeek version does not define
// ZEEK_VERSION_NUMBER through zeek-config.h, it'll be in the new
// zeek/zeek-version.h header.
#if __has_include(<zeek/zeek-version.h>)
#include <zeek/zeek-version.h>
#endif

#if ZEEK_SPICY_VERSION_NUMBER != ZEEK_VERSION_NUMBER
#define STR(x) __STR(x)
#define __STR(x) #x
#pragma message "Zeek version " STR(ZEEK_SPICY_VERSION_NUMBER) " vs " STR(ZEEK_VERSION_NUMBER) ")"
#error "Mismatch in Zeek version numbers"
#undef __STR
#undef STR
#endif

//// Collect all the Zeek includes here that we need anywhere in the plugin.

#if ZEEK_DEBUG_BUILD
#ifndef DEBUG
#define SPICY_PLUGIN_DEBUG_DEFINED
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

#ifdef SPICY_PLUGIN_DEBUG_DEFINED
#undef DEBUG
#undef SPICY_PLUGIN_DEBUG_DEFINED
#endif

//// Import types and globals into the new namespaces.

#if ZEEK_VERSION_NUMBER < 50100 // Zeek < 5.1
using zeek_int_t = bro_int_t;
#endif
