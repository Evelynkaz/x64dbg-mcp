#include "nlohmann/json.hpp"
#include "doctest/doctest.h"

TEST_CASE("json: round-trip of an object") {
    // Build an object with fields of different types: string, number, nested object, array.
    nlohmann::json original = {
        {"name", "x64dbg-mcp"},
        {"version", 1},
        {"nested", {{"enabled", true}}},
        {"values", {1, 2, 3}}
    };

    // Serialize to a string and parse it back.
    const std::string text = original.dump();
    const nlohmann::json parsed = nlohmann::json::parse(text);

    CHECK(parsed["name"] == "x64dbg-mcp");
    CHECK(parsed["version"] == 1);
    CHECK(parsed["nested"]["enabled"] == true);
    CHECK(parsed["values"] == nlohmann::json::array({1, 2, 3}));
}

TEST_CASE("json: parsing invalid input does not throw when using safe parsing") {
    // Input data comes from outside, and parsing must not throw an exception
    // that escapes the handler.
    const std::string broken = "{\"key\": ";
    const nlohmann::json result = nlohmann::json::parse(broken, nullptr, false);

    CHECK(result.is_discarded());
}

TEST_CASE("json: unicode and escaping survive a round trip") {
    // MCP messages are transmitted line by line, so it matters that newlines
    // inside values are escaped and do not split the protocol across multiple lines.
    const std::string original = "Привет \"мир\"\\\nновая строка";
    nlohmann::json value = original;

    const std::string text = value.dump();
    const nlohmann::json parsed = nlohmann::json::parse(text);

    CHECK(parsed.get<std::string>() == original);
    CHECK(text.find('\n') == std::string::npos);
}
