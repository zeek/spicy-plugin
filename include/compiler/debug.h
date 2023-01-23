// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/base/logger.h>

// Debug stream for compiler messages.
static const ::hilti::logging::DebugStream ZeekPlugin("zeek");

// Macro helper to report debug messages.
#define ZEEK_DEBUG(msg) HILTI_DEBUG(ZeekPlugin, std::string(msg));
