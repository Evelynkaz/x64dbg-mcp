# Скачивает официальный x64dbg Plugin SDK. Архив содержит собственный
# CMakeLists.txt, который определяет интерфейсную цель `x64dbg` и функцию
# `x64dbg_plugin(<target> <sources...>)`. SDK намеренно не вендорится в
# репозиторий — он загружается на этапе конфигурации через FetchContent.
include(FetchContent)

FetchContent_Declare(x64dbg_sdk
    URL https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/x64dbg-pluginsdk-cmake.zip
    URL_HASH SHA256=b669d6364816cbaed5257adad0df34a98a1791810a81941191d6f4aea74eb04e
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(x64dbg_sdk)
