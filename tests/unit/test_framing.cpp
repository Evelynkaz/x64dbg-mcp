#include "common/framing.h"
#include "doctest/doctest.h"

#include <cstdint>

using x64dbg_mcp::EncodeFrame;
using x64dbg_mcp::FrameReader;
using x64dbg_mcp::kMaxFrameSize;

TEST_CASE("framing: encodes and parses a single frame") {
    const std::string payload = "hello, x64dbg-mcp";
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));

    FrameReader reader;
    CHECK(reader.Feed(encoded.data(), encoded.size()) == FrameReader::Status::Ok);

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
}

TEST_CASE("framing: zero-length frame is encoded and extracted as an empty string") {
    const std::string payload;
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));
    CHECK(encoded.size() == x64dbg_mcp::kFrameHeaderSize);

    FrameReader reader;
    reader.Feed(encoded.data(), encoded.size());

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded.empty());
}

TEST_CASE("framing: two frames delivered in one chunk are extracted in order") {
    std::string first;
    std::string second;
    REQUIRE(EncodeFrame("first", first));
    REQUIRE(EncodeFrame("second frame", second));

    FrameReader reader;
    const std::string chunk = first + second;
    reader.Feed(chunk.data(), chunk.size());

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == "first");

    REQUIRE(reader.Next(decoded));
    CHECK(decoded == "second frame");

    CHECK_FALSE(reader.Next(decoded));
}

TEST_CASE("framing: frame fed one byte at a time is assembled correctly") {
    const std::string payload = "byte-by-byte";
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));

    FrameReader reader;
    std::string decoded;
    for (size_t i = 0; i + 1 < encoded.size(); ++i)
    {
        reader.Feed(&encoded[i], 1);
        CHECK_FALSE(reader.Next(decoded));
    }

    // The last byte completes the whole frame.
    reader.Feed(&encoded[encoded.size() - 1], 1);
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
}

TEST_CASE("framing: split in the middle of the length prefix") {
    const std::string payload = "split header";
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));

    FrameReader reader;
    // Feed only the first 2 bytes of the 4-byte prefix.
    reader.Feed(encoded.data(), 2);

    std::string decoded;
    CHECK_FALSE(reader.Next(decoded));

    // The rest of the prefix plus the whole payload — as a second chunk.
    reader.Feed(encoded.data() + 2, encoded.size() - 2);
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
}

TEST_CASE("framing: declared length greater than kMaxFrameSize causes Overflow") {
    // Build the prefix by hand: kMaxFrameSize + 1, little-endian.
    const uint32_t declaredLength = static_cast<uint32_t>(kMaxFrameSize) + 1;
    char header[4];
    header[0] = static_cast<char>(declaredLength & 0xFF);
    header[1] = static_cast<char>((declaredLength >> 8) & 0xFF);
    header[2] = static_cast<char>((declaredLength >> 16) & 0xFF);
    header[3] = static_cast<char>((declaredLength >> 24) & 0xFF);

    FrameReader reader;
    CHECK(reader.Feed(header, sizeof(header)) == FrameReader::Status::Overflow);
    CHECK(reader.Failed());

    std::string decoded;
    CHECK_FALSE(reader.Next(decoded));
}

TEST_CASE("framing: EncodeFrame encodes a small example correctly") {
    // We won't test the real kMaxFrameSize limit (64 MB) here —
    // that would require allocating tens of megabytes in the test.
    // It's enough to confirm that EncodeFrame builds a correct frame
    // (prefix + data) for a small payload.
    const std::string payload(1000, 'x');
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));
    CHECK(encoded.size() == x64dbg_mcp::kFrameHeaderSize + payload.size());

    FrameReader reader;
    reader.Feed(encoded.data(), encoded.size());
    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
}

TEST_CASE("framing: buffer is empty after extracting all frames") {
    std::string first;
    std::string second;
    REQUIRE(EncodeFrame("one", first));
    REQUIRE(EncodeFrame("two", second));

    FrameReader reader;
    reader.Feed(first.data(), first.size());
    reader.Feed(second.data(), second.size());

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    REQUIRE(reader.Next(decoded));

    CHECK(reader.Buffered() == 0);
}

TEST_CASE("framing: binary data with null bytes survives a round trip") {
    const std::string payload = std::string("abc\0def", 7);
    REQUIRE(payload.size() == 7);

    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));

    FrameReader reader;
    reader.Feed(encoded.data(), encoded.size());

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded.size() == 7);
    CHECK(decoded == payload);
}

// Catches a defect in casting the prefix bytes: if any of bytes 1..3
// is read as a signed char with the high bit set, the frame length is
// assembled incorrectly (sign-extended), and the round-trip breaks.
TEST_CASE("framing: high bit in length-prefix bytes does not break the round trip") {
    auto makePayload = [](size_t n) {
        std::string payload(n, '\0');
        for (size_t i = 0; i < n; ++i)
            payload[i] = static_cast<char>(i & 0xFF);
        return payload;
    };

    // 32768 = 0x8000 -> prefix 00 80 00 00, second byte has the high bit set.
    {
        const std::string payload = makePayload(32768);
        std::string encoded;
        REQUIRE(EncodeFrame(payload, encoded));
        REQUIRE(static_cast<unsigned char>(encoded[0]) == 0x00);
        REQUIRE(static_cast<unsigned char>(encoded[1]) == 0x80);
        REQUIRE(static_cast<unsigned char>(encoded[2]) == 0x00);
        REQUIRE(static_cast<unsigned char>(encoded[3]) == 0x00);

        FrameReader reader;
        CHECK(reader.Feed(encoded.data(), encoded.size()) == FrameReader::Status::Ok);

        std::string decoded;
        REQUIRE(reader.Next(decoded));
        CHECK(decoded.size() == payload.size());
        CHECK(decoded == payload);
    }

    // 65408 = 0xFF80 -> prefix 80 FF 00 00, first and second bytes have the high bit set.
    {
        const std::string payload = makePayload(65408);
        std::string encoded;
        REQUIRE(EncodeFrame(payload, encoded));
        REQUIRE(static_cast<unsigned char>(encoded[0]) == 0x80);
        REQUIRE(static_cast<unsigned char>(encoded[1]) == 0xFF);
        REQUIRE(static_cast<unsigned char>(encoded[2]) == 0x00);
        REQUIRE(static_cast<unsigned char>(encoded[3]) == 0x00);

        FrameReader reader;
        CHECK(reader.Feed(encoded.data(), encoded.size()) == FrameReader::Status::Ok);

        std::string decoded;
        REQUIRE(reader.Next(decoded));
        CHECK(decoded.size() == payload.size());
        CHECK(decoded == payload);
    }
}

// Boundary of the limit: a length of exactly kMaxFrameSize must be accepted
// by the header (must not be falsely detected as overflow).
TEST_CASE("framing: header with length exactly kMaxFrameSize is accepted") {
    const uint32_t declaredLength = static_cast<uint32_t>(kMaxFrameSize);
    char header[4];
    header[0] = static_cast<char>(declaredLength & 0xFF);
    header[1] = static_cast<char>((declaredLength >> 8) & 0xFF);
    header[2] = static_cast<char>((declaredLength >> 16) & 0xFF);
    header[3] = static_cast<char>((declaredLength >> 24) & 0xFF);

    FrameReader reader;
    CHECK(reader.Feed(header, sizeof(header)) == FrameReader::Status::Ok);
    CHECK_FALSE(reader.Failed());
    CHECK(reader.Buffered() == 4);
}

// Boundary of the limit: a length of kMaxFrameSize + 1 must be rejected.
TEST_CASE("framing: header with length kMaxFrameSize + 1 is rejected") {
    const uint32_t declaredLength = static_cast<uint32_t>(kMaxFrameSize) + 1;
    char header[4];
    header[0] = static_cast<char>(declaredLength & 0xFF);
    header[1] = static_cast<char>((declaredLength >> 8) & 0xFF);
    header[2] = static_cast<char>((declaredLength >> 16) & 0xFF);
    header[3] = static_cast<char>((declaredLength >> 24) & 0xFF);

    FrameReader reader;
    CHECK(reader.Feed(header, sizeof(header)) == FrameReader::Status::Overflow);
    CHECK(reader.Failed());
}

// Verifies the fix for defect 2: an invalid header following a valid frame,
// fed as a single chunk, must be detected right in Feed, not silently
// result in a quiet false from Next().
TEST_CASE("framing: overflow is detected at the tail of the buffer") {
    std::string good;
    REQUIRE(EncodeFrame("ok frame", good));

    const uint32_t badLength = static_cast<uint32_t>(kMaxFrameSize) + 1;
    char badHeader[4];
    badHeader[0] = static_cast<char>(badLength & 0xFF);
    badHeader[1] = static_cast<char>((badLength >> 8) & 0xFF);
    badHeader[2] = static_cast<char>((badLength >> 16) & 0xFF);
    badHeader[3] = static_cast<char>((badLength >> 24) & 0xFF);

    const std::string chunk = good + std::string(badHeader, sizeof(badHeader));

    FrameReader reader;
    CHECK(reader.Feed(chunk.data(), chunk.size()) == FrameReader::Status::Overflow);
    CHECK(reader.Failed());
}

// After entering Failed(), the parser must keep responding with Overflow
// and stop accumulating more data in the buffer.
TEST_CASE("framing: reception stops after a failure") {
    const uint32_t badLength = static_cast<uint32_t>(kMaxFrameSize) + 1;
    char header[4];
    header[0] = static_cast<char>(badLength & 0xFF);
    header[1] = static_cast<char>((badLength >> 8) & 0xFF);
    header[2] = static_cast<char>((badLength >> 16) & 0xFF);
    header[3] = static_cast<char>((badLength >> 24) & 0xFF);

    FrameReader reader;
    CHECK(reader.Feed(header, sizeof(header)) == FrameReader::Status::Overflow);
    REQUIRE(reader.Failed());

    const size_t bufferedBefore = reader.Buffered();
    const std::string more = "more data";
    CHECK(reader.Feed(more.data(), more.size()) == FrameReader::Status::Overflow);
    CHECK(reader.Buffered() == bufferedBefore);
}

// Feed(nullptr, 0) must not lead to undefined behavior.
TEST_CASE("framing: Feed(nullptr, 0) is safe") {
    FrameReader reader;
    CHECK(reader.Feed(nullptr, 0) == FrameReader::Status::Ok);
    CHECK_FALSE(reader.Failed());
    CHECK(reader.Buffered() == 0);
}

// Verifies the fix for defect 4: EncodeFrame(s, s) must not corrupt the data.
TEST_CASE("framing: EncodeFrame with aliased arguments encodes in place correctly") {
    std::string s = "encode in place";
    const std::string original = s;
    REQUIRE(EncodeFrame(s, s));

    FrameReader reader;
    CHECK(reader.Feed(s.data(), s.size()) == FrameReader::Status::Ok);

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == original);
}

// Verifies the fix for defect 3: after extracting a large frame, the buffer
// capacity must be released, not held onto forever.
TEST_CASE("framing: buffer capacity is reclaimed after a large frame") {
    const std::string payload(128 * 1024, 'z');
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));

    FrameReader reader;
    CHECK(reader.Feed(encoded.data(), encoded.size()) == FrameReader::Status::Ok);

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
    CHECK(reader.Buffered() == 0);
    CHECK(reader.Capacity() <= x64dbg_mcp::kBufferShrinkThreshold);

    // Make sure the parser still handles small frames correctly after shrinking.
    std::string small;
    REQUIRE(EncodeFrame("still works", small));
    CHECK(reader.Feed(small.data(), small.size()) == FrameReader::Status::Ok);
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == "still works");
}
