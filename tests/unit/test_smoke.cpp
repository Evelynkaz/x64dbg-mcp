#include "nlohmann/json.hpp"
#include "doctest/doctest.h"

TEST_CASE("json: round-trip объекта") {
    // Строим объект с полями разных типов: строка, число, вложенный объект, массив.
    nlohmann::json original = {
        {"name", "x64dbg-mcp"},
        {"version", 1},
        {"nested", {{"enabled", true}}},
        {"values", {1, 2, 3}}
    };

    // Сериализуем в строку и разбираем обратно.
    const std::string text = original.dump();
    const nlohmann::json parsed = nlohmann::json::parse(text);

    CHECK(parsed["name"] == "x64dbg-mcp");
    CHECK(parsed["version"] == 1);
    CHECK(parsed["nested"]["enabled"] == true);
    CHECK(parsed["values"] == nlohmann::json::array({1, 2, 3}));
}

TEST_CASE("json: разбор некорректного ввода не бросает при использовании безопасного разбора") {
    // Входные данные приходят снаружи, и разбор не должен приводить к исключению,
    // вылетающему за пределы обработчика.
    const std::string broken = "{\"key\": ";
    const nlohmann::json result = nlohmann::json::parse(broken, nullptr, false);

    CHECK(result.is_discarded());
}

TEST_CASE("json: юникод и экранирование переживают round-trip") {
    // Сообщения MCP передаются построчно, поэтому важно, что переводы строк
    // внутри значений экранируются и не разрывают протокол на несколько строк.
    const std::string original = "Привет \"мир\"\\\nновая строка";
    nlohmann::json value = original;

    const std::string text = value.dump();
    const nlohmann::json parsed = nlohmann::json::parse(text);

    CHECK(parsed.get<std::string>() == original);
    CHECK(text.find('\n') == std::string::npos);
}
