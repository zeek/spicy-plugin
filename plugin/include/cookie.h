// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

/**
 * Cookie types that's stored in the HILTI context to provide access to the
 * current analyzer.
 */

#pragma once

#include <optional>
#include <string>
#include <utility>
#include <variant>

#include <hilti/rt/fmt.h>

#include <zeek-spicy/zeek-compat.h>

namespace spicy::zeek::rt {

namespace cookie {

/** State stored inside protocol/file analyzer cookies to retain file analysis state. */
struct FileState {
    FileState(std::string analyzer_id) : analyzer_id(std::move(analyzer_id)) {}
    std::string analyzer_id; /**< unique analyzer ID */
    uint64_t file_id = 0;    /**< counter incremented for each file processed by this analyzer */

    /**
     * Computes the Zeek-side file ID for the current state (which will be
     * hashed further before passing on to Zeek.)
     */
    std::string id() const {
        auto id = hilti::rt::fmt("%s.%" PRIu64 ".%d", analyzer_id, file_id);
        return ::zeek::file_mgr->HashHandle(id);
    }
};

/** State on the current protocol analyzer. */
struct ProtocolAnalyzer {
    ::zeek::analyzer::Analyzer* analyzer = nullptr; /**< current analyzer */
    bool is_orig = false;                           /**< direction of the connection */
    uint64_t num_packets = 0;                       /**< number of packets seen so far */
    FileState fstate_orig;                          /**< file analysis state for originator side */
    FileState fstate_resp;                          /**< file analysis state for responder side */
};

/** State on the current file analyzer. */
struct FileAnalyzer {
    ::zeek::file_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
    FileState fstate;                                    /**< file analysis state for nested files */
};

#ifdef HAVE_PACKET_ANALYZERS
/** State on the current file analyzer. */
struct PacketAnalyzer {
    ::zeek::packet_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
    std::optional<uint32_t> next_analyzer;
};
#endif

} // namespace cookie

/** Type of state stored in HILTI's execution context during Spicy processing. */
#ifdef HAVE_PACKET_ANALYZERS
using Cookie = std::variant<cookie::ProtocolAnalyzer, cookie::FileAnalyzer, cookie::PacketAnalyzer>;
#else
using Cookie = std::variant<cookie::ProtocolAnalyzer, cookie::FileAnalyzer>;
#endif

} // namespace spicy::zeek::rt
