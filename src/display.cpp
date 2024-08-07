#include "display.hpp"
#include <windows.h>
#include <iostream>

// Static definition
std::mutex Display::s_writeToScreenMutex;

void Display::s_SetTerminalModeRaw(void)
{
#ifdef _WIN32
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hInput, &mode);
    mode &= ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(hInput, mode);
#else
    // Unix not implemented
#endif
}

void Display::s_SetTerminalModeReset(void)
{
#ifdef _WIN32
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hInput, &mode);
    mode |= (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(hInput, mode);
#else
    // Unix not implemented
#endif
}

void Display::s_GetConsoleMaxCoords(short &columns, short &rows)
{
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    columns = csbi.srWindow.Right - csbi.srWindow.Left;
    rows = csbi.srWindow.Bottom - csbi.srWindow.Top;
#else
    // Unix not implemented
#endif
}

bool Display::s_GoToXY(const short x_col, const short y_row)
{
#ifdef _WIN32
    COORD position = { x_col, y_row };
    return SetConsoleCursorPosition( GetStdHandle( STD_OUTPUT_HANDLE ), position );
#else
    // Unix not implemented
#endif
}

void Display::s_ClearTerminal(void)
{
#ifdef _WIN32
    system("cls");
#else
    // Unix not implemented
#endif
}

void Display::s_Draw(std::mutex& writeToScreenMutex)
{
    std::lock_guard<std::mutex> lock(writeToScreenMutex);

    short columns, rows;
    s_GetConsoleMaxCoords(columns, rows);

    for (int i = 1; i < columns; i++)
    {
        s_GoToXY(i, 0);
        std::cout << wholeBlockChar;
        s_GoToXY(i, rows-2);
        std::cout << upperBlockChar; 
        s_GoToXY(i, rows);
        std::cout << lowerBlockChar;
    }
    // Top and bottom corners already done
    for (int i = 0; i < rows+1; i++)
    {
        s_GoToXY(0, i);
        std::cout << wholeBlockChar;
        s_GoToXY(columns, i);
        std::cout << wholeBlockChar;
    }
    // Position of the input part
    // s_goToXY(1,rows-1);

    // auto buffer = getInputBuffer();
    // std::cout << buffer;
    // s_goToXY(buffer.size()+1, rows-1);
}

void Display::s_WriteToScreen(std::mutex writeToScreenMutex, short x_col, short y_row, std::string& msg)
{
    std::lock_guard<std::mutex> lock(writeToScreenMutex);

    s_GoToXY(x_col, y_row);
    std::cout << msg;
}
