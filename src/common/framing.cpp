#include "common/framing.h"

#include <cstdint>

namespace x64dbg_mcp
{

namespace
{

// Пишет 32-битную длину в буфер побайтово, little-endian, без reinterpret_cast.
void AppendLengthLE(uint32_t length, std::string& out)
{
    out.push_back(static_cast<char>(length & 0xFF));
    out.push_back(static_cast<char>((length >> 8) & 0xFF));
    out.push_back(static_cast<char>((length >> 16) & 0xFF));
    out.push_back(static_cast<char>((length >> 24) & 0xFF));
}

// Читает 32-битную длину из буфера побайтово, little-endian.
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

    // Собираем результат во временной строке и присваиваем в конце, чтобы
    // EncodeFrame(s, s) (кодирование "на месте") не затирал payload раньше
    // времени: out.clear() до чтения payload испортил бы данные, если out
    // и payload — один и тот же объект.
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

    // Проверяется только внешними прогонами: MSVC терпит append(nullptr, 0)
    // и без этой проверки, поэтому юнит-тестами регрессию здесь не поймать.
    if (size == 0)
        return Status::Ok;

    // Этот код исполняется внутри процесса плагина x64dbg, на потоке,
    // обслуживающем канал к отлаживаемому процессу. Любое исключение
    // (в первую очередь std::bad_alloc при нехватке адресного пространства
    // в 32-битной сборке), вышедшее наружу отсюда, приведёт к std::terminate
    // и уронит отладчик вместе с отлаживаемым процессом — поэтому здесь
    // ловится всё подряд.
    // Проверяется только внешними прогонами: нехватку памяти (std::bad_alloc)
    // в юнит-тесте воспроизвести нельзя, поэтому этот try/catch тестами
    // не покрыт.
    try
    {
        buffer_.append(data, size);

        // Проверяем заголовки всех полностью принятых кадров, а не только
        // первого — иначе повреждённый заголовок за пределами первого кадра
        // будет обнаружен только в Next(), которая тихо вернёт false, и
        // вызывающий код, дренирующий буфер в цикле while(Next(...)), решит,
        // что сообщений просто нет, и зависнет. scanOffset_ хранит границу,
        // до которой заголовки уже проверены, чтобы не пересканировать буфер
        // заново на каждый вызов (иначе поток мелких кадров даёт
        // квадратичную сложность).
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
                break; // кадр ещё не пришёл целиком

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

    // См. комментарий к try/catch в Feed — то же самое исключение по той же
    // причине не должно покидать разборщик.
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

        // Возвращаем ёмкость буфера, если крупный кадр уже обработан и
        // буфер опустел — иначе память, выделенную под одно большое
        // сообщение, буфер удерживал бы до конца своей жизни.
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
