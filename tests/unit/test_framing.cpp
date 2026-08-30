#include "common/framing.h"
#include "doctest/doctest.h"

#include <cstdint>

using x64dbg_mcp::EncodeFrame;
using x64dbg_mcp::FrameReader;
using x64dbg_mcp::kMaxFrameSize;

TEST_CASE("framing: кодирование и разбор одного кадра") {
    const std::string payload = "hello, x64dbg-mcp";
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));

    FrameReader reader;
    CHECK(reader.Feed(encoded.data(), encoded.size()) == FrameReader::Status::Ok);

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
}

TEST_CASE("framing: кадр нулевой длины кодируется и извлекается как пустая строка") {
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

TEST_CASE("framing: два кадра одним куском извлекаются по очереди") {
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

TEST_CASE("framing: кадр, поданный по одному байту, собирается правильно") {
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

    // Последний байт достраивает кадр целиком.
    reader.Feed(&encoded[encoded.size() - 1], 1);
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
}

TEST_CASE("framing: разрыв посередине префикса длины") {
    const std::string payload = "split header";
    std::string encoded;
    REQUIRE(EncodeFrame(payload, encoded));

    FrameReader reader;
    // Подаём только первые 2 байта из 4-байтового префикса.
    reader.Feed(encoded.data(), 2);

    std::string decoded;
    CHECK_FALSE(reader.Next(decoded));

    // Остаток префикса и всю полезную нагрузку — вторым куском.
    reader.Feed(encoded.data() + 2, encoded.size() - 2);
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == payload);
}

TEST_CASE("framing: объявленная длина больше kMaxFrameSize приводит к Overflow") {
    // Формируем префикс вручную: kMaxFrameSize + 1, little-endian.
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

TEST_CASE("framing: EncodeFrame на малом примере кодирует корректно") {
    // Проверять реальный предел kMaxFrameSize (64 МБ) здесь не будем —
    // это потребовало бы выделения десятков мегабайт в тесте.
    // Достаточно убедиться, что EncodeFrame формирует корректный кадр
    // (префикс + данные) для некрупной полезной нагрузки.
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

TEST_CASE("framing: после извлечения всех кадров буфер пуст") {
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

TEST_CASE("framing: двоичные данные с нулевыми байтами переживают round-trip") {
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

// Ловит дефект в приведении байтов префикса: если хотя бы один из байтов
// 1..3 читается как signed char со старшим битом, длина кадра собирается
// неверно (расширяется знаком), и round-trip ломается.
TEST_CASE("framing: старший бит в байтах префикса длины не портит round-trip") {
    auto makePayload = [](size_t n) {
        std::string payload(n, '\0');
        for (size_t i = 0; i < n; ++i)
            payload[i] = static_cast<char>(i & 0xFF);
        return payload;
    };

    // 32768 = 0x8000 -> префикс 00 80 00 00, второй байт со старшим битом.
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

    // 65408 = 0xFF80 -> префикс 80 FF 00 00, первый и второй байты со старшим битом.
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

// Граница предела: длина ровно kMaxFrameSize должна приниматься заголовком
// (не должна ложно детектироваться как переполнение).
TEST_CASE("framing: заголовок с длиной ровно kMaxFrameSize принимается") {
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

// Граница предела: длина kMaxFrameSize + 1 должна отвергаться.
TEST_CASE("framing: заголовок с длиной kMaxFrameSize + 1 отвергается") {
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

// Проверка исправления дефекта 2: недопустимый заголовок после корректного
// кадра, поданные одним куском, должен обнаруживаться в самом Feed, а не
// тихо приводить к молчаливому false в Next().
TEST_CASE("framing: переполнение обнаруживается в хвосте буфера") {
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

// После перехода в Failed() разборщик должен и дальше отвечать Overflow,
// не накапливая больше данных в буфере.
TEST_CASE("framing: после отказа приём прекращается") {
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

// Feed(nullptr, 0) не должен приводить к неопределённому поведению.
TEST_CASE("framing: Feed(nullptr, 0) безопасен") {
    FrameReader reader;
    CHECK(reader.Feed(nullptr, 0) == FrameReader::Status::Ok);
    CHECK_FALSE(reader.Failed());
    CHECK(reader.Buffered() == 0);
}

// Проверка исправления дефекта 4: EncodeFrame(s, s) не должен портить данные.
TEST_CASE("framing: EncodeFrame с совпадающими аргументами кодирует на месте корректно") {
    std::string s = "encode in place";
    const std::string original = s;
    REQUIRE(EncodeFrame(s, s));

    FrameReader reader;
    CHECK(reader.Feed(s.data(), s.size()) == FrameReader::Status::Ok);

    std::string decoded;
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == original);
}

// Проверка исправления дефекта 3: после извлечения крупного кадра ёмкость
// буфера должна возвращаться, а не удерживаться навсегда.
TEST_CASE("framing: ёмкость буфера возвращается после крупного кадра") {
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

    // Убедимся, что разборщик после сжатия по-прежнему корректно работает
    // с мелкими кадрами.
    std::string small;
    REQUIRE(EncodeFrame("still works", small));
    CHECK(reader.Feed(small.data(), small.size()) == FrameReader::Status::Ok);
    REQUIRE(reader.Next(decoded));
    CHECK(decoded == "still works");
}
