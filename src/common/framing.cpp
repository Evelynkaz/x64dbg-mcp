#include "common/framing.h"

#include <cstdint>

namespace x64dbg_mcp
{

namespace
{

// Writes a 32-bit length into the buffer byte by byte, little-endian, without reinterpret_cast.
void AppendLengthLE(uint32_t length, std::string& out)
{
    out.push_back(static_cast<char>(length & 0xFF));
    out.push_back(static_cast<char>((length >> 8) & 0xFF));
    out.push_back(static_cast<char>((length >> 16) & 0xFF));
    out.push_back(static_cast<char>((length >> 24) & 0xFF));
}

// Reads a 32-bit length from the buffer byte by byte, little-endian.
uint32_t ReadLengthLE(const char* data)
{
    return (static_cast<uint32_t>(static_cast<unsigned char>(data[0]))) |
           (static_cast<uint32_t>(static_cast<unsigned char>(data[1])) << 8) |
           (static_cast<uint32_t>(static_cast<unsigned char>(data[2])) << 16) |
           (static_cast<uint32_t>(static_cast<unsigned char>(data[3])) << 24);
}

} // namespace

bool EncodeFrame(const std::string& payload, std::string& out)
{
    if (payload.size() > kMaxFrameSize)
        return false;

    // Assemble the result into a temporary string and assign it at the end,
    // so that EncodeFrame(s, s) (encoding "in place") doesn't clobber payload
    // too early: an out.clear() before reading payload would corrupt the
    // data if out and payload are the same object.
    try
    {
        const size_t n = payload.size();
        std::string frame;
        frame.reserve(kFrameHeaderSize + n);
        AppendLengthLE(static_cast<uint32_t>(n), frame);
        frame.append(payload);
        out = std::move(frame);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

FrameReader::Status FrameReader::Feed(const char* data, size_t size)
{
    if (failed_)
        return Status::Overflow;

    // Only exercised by external runs: MSVC tolerates append(nullptr, 0)
    // even without this check, so a unit test can't catch a regression here.
    if (size == 0)
        return Status::Ok;

    // This code runs inside the x64dbg plugin process, on the thread that
    // services the channel to the debuggee. Any exception (most notably
    // std::bad_alloc from running out of address space in a 32-bit build)
    // escaping from here would call std::terminate and take down the
    // debugger along with the debuggee — hence catching everything here.
    // Only exercised by external runs: an out-of-memory condition
    // (std::bad_alloc) can't be reproduced in a unit test, so this
    // try/catch isn't covered by tests.
    try
    {
        buffer_.append(data, size);

        // Check the headers of every fully-received frame, not just the
        // first — otherwise a corrupted header past the first frame would
        // only surface in Next(), which would quietly return false, and the
        // caller draining the buffer in a while(Next(...)) loop would
        // conclude there's simply no message and hang. scanOffset_ tracks
        // the boundary up to which headers have already been checked, so we
        // don't rescan the buffer on every call (otherwise a stream of
        // small frames would give quadratic complexity).
        while (buffer_.size() - scanOffset_ >= kFrameHeaderSize)
        {
            const uint32_t len = ReadLengthLE(buffer_.data() + scanOffset_);
            if (len > kMaxFrameSize)
            {
                failed_ = true;
                return Status::Overflow;
            }

            const size_t total = kFrameHeaderSize + static_cast<size_t>(len);
            if (buffer_.size() - scanOffset_ < total)
                break; // the frame hasn't arrived in full yet

            scanOffset_ += total;
        }

        return Status::Ok;
    }
    catch (...)
    {
        failed_ = true;
        return Status::Overflow;
    }
}

bool FrameReader::Next(std::string& payload)
{
    if (failed_)
        return false;

    if (buffer_.size() < kFrameHeaderSize)
        return false;

    // See the try/catch comment in Feed — the same exception, for the same
    // reason, must not escape the parser.
    try
    {
        const uint32_t frameLength = ReadLengthLE(buffer_.data());
        if (frameLength > kMaxFrameSize)
        {
            failed_ = true;
            return false;
        }

        const size_t totalSize = kFrameHeaderSize + static_cast<size_t>(frameLength);
        if (buffer_.size() < totalSize)
            return false;

        payload.assign(buffer_, kFrameHeaderSize, frameLength);
        buffer_.erase(0, totalSize);
        scanOffset_ = (scanOffset_ >= totalSize) ? scanOffset_ - totalSize : 0;

        // Return the buffer's capacity if a large frame has just been
        // processed and the buffer is now empty — otherwise the memory
        // allocated for one big message would be held onto for the
        // buffer's entire lifetime.
        if (buffer_.empty() && buffer_.capacity() > kBufferShrinkThreshold)
        {
            std::string().swap(buffer_);
            scanOffset_ = 0;
        }

        return true;
    }
    catch (...)
    {
        failed_ = true;
        return false;
    }
}

bool FrameReader::Failed() const
{
    return failed_;
}

size_t FrameReader::Buffered() const
{
    return buffer_.size();
}

size_t FrameReader::Capacity() const
{
    return buffer_.capacity();
}

} // namespace x64dbg_mcp
