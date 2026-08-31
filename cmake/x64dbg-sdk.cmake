# Downloads the official x64dbg Plugin SDK. The archive contains its own
# CMakeLists.txt, which defines the interface target `x64dbg` and the function
# `x64dbg_plugin(<target> <sources...>)`. The SDK is deliberately not vendored
# into the repository — it is downloaded at configuration time via FetchContent.
include(FetchContent)

FetchContent_Declare(x64dbg_sdk
    URL https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/x64dbg-pluginsdk-cmake.zip
    URL_HASH SHA256=b669d6364816cbaed5257adad0df34a98a1791810a81941191d6f4aea74eb04e
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(x64dbg_sdk)
