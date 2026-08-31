#pragma once

#include <cstddef>
#include <string>

namespace x64dbg_mcp
{

// Frame prefix length: a 4-byte little-endian length of the payload.
constexpr size_t kFrameHeaderSize = 4;

// Limit on a single message. Needed so that a corrupted or hostile
// prefix can't force allocation of gigabytes of memory.
constexpr size_t kMaxFrameSize = 64u * 1024u * 1024u;

// Threshold below which shrinking the buffer isn't worth it — it would just grow back right away.
constexpr size_t kBufferShrinkThreshold = 64u * 1024u;

// Encodes the payload into a frame: a 4-byte little-endian length followed by the data itself.
// Returns false if payload exceeds kMaxFrameSize.
bool EncodeFrame(const std::string& payload, std::string& out);

// A streaming frame parser. Accumulates arbitrary chunks of bytes
// and yields complete messages as they arrive.
class FrameReader
{
public:
    enum class Status { Ok, Overflow };

    // Appends another chunk of received bytes to the internal buffer.
    // Returns Overflow in three cases: the declared frame length exceeds
    // kMaxFrameSize; the buffer allocation failed (std::bad_alloc);
    // the parser is already in a failed state from one of the previous
    // cases. In all three, further parsing is impossible and the connection
    // must be closed; don't treat Overflow as unconditional proof of a hostile peer.
    Status Feed(const char* data, size_t size);

    // Extracts the next complete frame. Returns false if a full frame isn't available yet.
    bool Next(std::string& payload);

    // The parser has entered an irrecoverably broken state.
    //
    // Intentional frame loss: if Feed finds an invalid header near the tail
    // of the buffer, the parser goes into a failed state, and correct frames
    // already sitting in the buffer BEFORE the bad header are no longer
    // handed out — they are silently dropped. This is a deliberate choice,
    // not an oversight: an invalid header means the stream has desynced or
    // the peer is broken. The contents of such a stream can't be trusted,
    // including frames received before the bad header was found — the
    // desync could have started earlier, and a "correct" frame in front of
    // the bad header might have been parsed from a coincidental byte match.
    // The connection has to be closed either way, so delivering a response
    // over it is pointless. Failing outright is safer than partially
    // processing data whose integrity is already compromised.
    bool Failed() const;

    // How many bytes currently sit in the buffer (for diagnostics and tests).
    size_t Buffered() const;

    // Current capacity of the internal buffer. Needed so tests can verify
    // memory is released after processing a large frame — otherwise there's no way to see that from outside.
    size_t Capacity() const;

private:
    std::string buffer_;
    bool failed_ = false;
    // Boundary in buffer_ up to which frame headers have already been checked
    // against kMaxFrameSize. Lets Feed avoid rescanning the buffer from the
    // start on every call — otherwise a stream of small messages would give
    // quadratic complexity.
    size_t scanOffset_ = 0;
};

} // namespace x64dbg_mcp
