#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace WXC
{

// Logger that can output to console or capture to string buffer
class Logger
{
public:
    enum class Mode
    {
        Console, // Output to std::wcout
        Buffer   // Capture to internal string buffer
    };

    explicit Logger(Mode mode = Mode::Console)
        : _mode(mode)
    {
    }

    // Write a wide string to the logger
    Logger& operator<<(const std::wstring& str)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << str;
        }
        else
        {
            _buffer << str;
        }
        return *this;
    }

    // Write a wide character to the logger
    Logger& operator<<(wchar_t ch)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << ch;
        }
        else
        {
            _buffer << ch;
        }
        return *this;
    }

    // Write a wstring_view to the logger
    Logger& operator<<(std::wstring_view value)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << value;
        }
        else
        {
            _buffer << value;
        }

        return *this;
    }

    // Write a C-style wide string to the logger
    Logger& operator<<(const wchar_t* str)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << str;
        }
        else
        {
            _buffer << str;
        }
        return *this;
    }

    // Write an integer to the logger
    Logger& operator<<(int value)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << value;
        }
        else
        {
            _buffer << value;
        }
        return *this;
    }

    // Write a DWORD to the logger
    Logger& operator<<(DWORD value)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << value;
        }
        else
        {
            _buffer << value;
        }
        return *this;
    }

    // Write a long to the logger
    Logger& operator<<(long value)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << value;
        }
        else
        {
            _buffer << value;
        }
        return *this;
    }

    // Write a size_t to the logger
    Logger& operator<<(size_t value)
    {
        if (_mode == Mode::Console)
        {
            std::wcout << value;
        }
        else
        {
            _buffer << value;
        }
        return *this;
    }

    // Convenience method for writing a line
    void WriteLine(const std::wstring& line) { *this << line << L"\n"; }

    // Get the captured buffer contents (only meaningful in Buffer mode)
    std::wstring GetBuffer() const { return _buffer.str(); }

    // Clear the buffer
    void ClearBuffer()
    {
        _buffer.str(L"");
        _buffer.clear();
    }

    // Get the current mode
    Mode GetMode() const { return _mode; }

    // Set the mode
    void SetMode(Mode mode) { _mode = mode; }

private:
    Mode _mode;
    std::wstringstream _buffer;
};

} // namespace WXC
