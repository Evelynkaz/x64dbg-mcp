#pragma once

#include "nlohmann/json.hpp"

#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace x64dbg_mcp::bridge
{

// Ошибка выполнения инструмента. Сообщение прочитает модель, а не только
// человек: оно должно объяснять причину сбоя и подсказывать, что сделать,
// чтобы операция удалась (например, каким методом сперва подключиться).
class ToolError : public std::runtime_error
{
public:
    explicit ToolError(const std::string& message);
};

// Описание одного инструмента, доступного модели через tools/list и tools/call.
struct Tool
{
    std::string name;
    std::string description;    // документация для модели: что делает, когда применять, что вернёт
    nlohmann::json inputSchema; // JSON Schema 2020-12
    std::function<nlohmann::json(const nlohmann::json& arguments)> handler;
};

class ToolRegistry
{
public:
    void Add(Tool tool);
    const Tool* Find(const std::string& name) const;
    nlohmann::json ListJson() const; // массив описаний для ответа tools/list
    size_t Size() const;

private:
    std::vector<Tool> tools_;
};

// Создаёт реестр со стандартным набором инструментов сервера.
ToolRegistry CreateDefaultRegistry();

} // namespace x64dbg_mcp::bridge
