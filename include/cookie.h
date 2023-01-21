// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

/**
 * Cookie types that's stored in the HILTI context to provide access to the
 * current analyzer.
 */

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <hilti/rt/fmt.h>

#include <zeek-spicy/zeek-compat.h>

namespace spicy::zeek::rt {

namespace cookie {

/** State representing analysis of one file. */
struct FileState {
    FileState(std::string fid) : fid(std::move(fid)) {}
    std::string fid;                      /**< unique Zeek-side file ID */
    std::optional<std::string> mime_type; /**< MIME type, if explicitly set */
};

/**
 * State stored inside protocol/file analyzer cookies retaining file analysis
 * state.
 *
 * Internally, this maintains a stack of state objects representing individual
 * files that are currently in-flight.
 */
class FileStateStack {
public:
    /**
     * Constructor.
     *
     * @param analyzer_id unique ID string representing parent connection/file analyzer
     */
    FileStateStack(std::string analyzer_id) : _analyzer_id(std::move(analyzer_id)) {}

    /**
     * Begins analysis for a new file, pushing a new state object onto the
     * stack.
     */
    FileState* push();

    /** Returns true if the stack is currently empty. */
    bool isEmpty() const { return _stack.empty(); }

    /**
     * Removes an object from the stack.
     *
     * @param fid ID of file to remove state for; no-op if not found
     */
    void remove(const std::string& fid);

    /**
     * Returns a pointer to the state of the most recently pushed file. Must not
     * be called on an empty stack.
     **/
    const FileState* current() const {
        assert(_stack.size());
        return &_stack.back();
    }

    /**
     * Returns the state of a given file currently on the stack.
     *
     * @param fid ID of file to find
     * @returns pointer to the file's state, or null if not found
     */
    const FileState* find(const std::string& fid) const;

private:
    std::vector<FileState> _stack; // stack of files in flight
    std::string _analyzer_id;      // unique ID string of parent analyzer, as passed into ctor
    uint64_t _id_counter = 0;      // counter incremented for each file added to this stack
};

/** State on the current protocol analyzer. */
struct ProtocolAnalyzer {
    ::zeek::analyzer::Analyzer* analyzer = nullptr; /**< current analyzer */
    bool is_orig = false;                           /**< direction of the connection */
    uint64_t num_packets = 0;                       /**< number of packets seen so far */
    FileStateStack fstate_orig;                     /**< file analysis state for originator side */
    FileStateStack fstate_resp;                     /**< file analysis state for responder side */
    std::shared_ptr<::zeek::packet_analysis::TCP::TCPSessionAdapter>
        fake_tcp; /**< fake TPC analyzer created internally */
};

/** State on the current file analyzer. */
struct FileAnalyzer {
    ::zeek::file_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
    uint64_t depth = 0;    /**< recursive depth of file analysis (Spicy-side file analysis only) */
    FileStateStack fstate; /**< file analysis state for nested files */
};

/** State on the current file analyzer. */
struct PacketAnalyzer {
    ::zeek::packet_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
    ::zeek::Packet* packet = nullptr;                      /**< current packet */
    ::zeek::ValPtr packet_val = nullptr;                   /**< cached "raw_pkt_hdr" val for packet */
    std::optional<uint32_t> next_analyzer;
};

} // namespace cookie

/** Type of state stored in HILTI's execution context during Spicy processing. */
using Cookie = std::variant<cookie::ProtocolAnalyzer, cookie::FileAnalyzer, cookie::PacketAnalyzer>;

} // namespace spicy::zeek::rt
