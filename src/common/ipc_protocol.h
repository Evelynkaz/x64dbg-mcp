#pragma once

// Формат сообщений моста и плагина.
//
// Запрос — объект с полями id, method, params.
// Ответ — объект с полями id, ok и либо result (при успехе), либо error (при ошибке).

namespace x64dbg_mcp::ipc
{

// Версия протокола обмена. Мажорная версия меняется при несовместимых
// изменениях; сторона с иной мажорной версией должна отказаться
// от соединения, а не пытаться работать.
constexpr int kProtocolVersionMajor = 1;
constexpr int kProtocolVersionMinor = 0;

// Имя именованного канала по умолчанию.
constexpr const char* kDefaultPipeName = R"(\\.\pipe\x64dbg-mcp)";

// Имена полей запроса.
constexpr const char* kFieldId = "id";
constexpr const char* kFieldMethod = "method";
constexpr const char* kFieldParams = "params";

// Имена полей ответа.
constexpr const char* kFieldOk = "ok";
constexpr const char* kFieldResult = "result";
constexpr const char* kFieldError = "error";

// Имена полей объекта ошибки.
constexpr const char* kFieldErrorCode = "code";
constexpr const char* kFieldErrorMessage = "message";

// Коды ошибок обмена.
enum class ErrorCode : int
{
    None = 0,
    InvalidRequest = 1,      // сообщение не разобралось или не хватает обязательных полей
    UnknownMethod = 2,       // метод не зарегистрирован
    NotDebugging = 3,        // отладка не запущена
    DebuggerBusy = 4,        // процесс сейчас выполняется, операция требует паузы
    InvalidArgument = 5,     // аргумент не прошёл проверку
    Timeout = 6,             // операция не уложилась в отведённое время
    OperationFailed = 7,     // отладчик отказался выполнить операцию
    Internal = 8,            // непредвиденный сбой внутри плагина
};

} // namespace x64dbg_mcp::ipc
