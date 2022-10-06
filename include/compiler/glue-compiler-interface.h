// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

namespace spicy::zeek {

namespace glue {
struct FileAnalyzer;
struct PacketAnalyzer;
struct ProtocolAnalyzer;

/**
 * Interface class enabling users of the `GlueCompiler` to define callbacks for
 * specific situations; `GlueCompiler` derives from this interface. To define
 * callbacks, derive from `GlueCompiler` and override the virtual methods in
 * your class. (The interface is split out only to avoid a cyclic header
 * depenency.)
 */
class GlueCompilerInterface {
protected:
    // Callback executing when a file analyzer has been parsed from an EVT
    // file. Note that no computed information will have been filled in
    // yet.
    virtual void newFileAnalyzer(const glue::FileAnalyzer& analyzer) {}

    // Callback executing when a packet analyzer has been parsed from an EVT
    // file. Note that no computed information will have been filled in
    // yet.
    virtual void newPacketAnalyzer(const glue::PacketAnalyzer& analyzer) {}

    // Callback executing when a protocol analyzer has been parsed from an EVT
    // file. Note that no computed information will have been filled in
    // yet.
    virtual void newProtocolAnalyzer(const glue::ProtocolAnalyzer& analyzer) {}
};

} // namespace glue
} // namespace spicy::zeek
