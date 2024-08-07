#include "display.hpp"
#include <windows.h>
#include <iostream>

void Display::s_setTerminalModeRaw(void)
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

void Display::s_setTerminalModeReset(void)
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

void Display::s_getConsoleMaxCoords(short &columns, short &rows)
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

bool Display::s_goToXY(const short x_col, const short y_row)
{
#ifdef _WIN32
    COORD position = { x_col, y_row };
    return SetConsoleCursorPosition( GetStdHandle( STD_OUTPUT_HANDLE ), position );
#else
    // Unix not implemented
#endif
}

void Display::s_clearTerminal(void)
{
#ifdef _WIN32
    system("cls");
#else
    // Unix not implemented
#endif
}

void Display::s_draw(void)
{
    const char boxDrawingChar = 0xDB;
    short columns, rows;
    s_getConsoleMaxCoords(columns, rows);

    for (int i = 1; i < columns; i++)
    {
        s_goToXY(i, 0);
        std::cout << wholeBlockChar;
        s_goToXY(i, rows-2);
        std::cout << upperBlockChar; 
        s_goToXY(i, rows);
        std::cout << lowerBlockChar;
    }
    // Top and bottom corners already done
    for (int i = 0; i < rows+1; i++)
    {
        s_goToXY(0, i);
        std::cout << wholeBlockChar;
        s_goToXY(columns, i);
        std::cout << wholeBlockChar;
    }
    // Position of the input part
    s_goToXY(1,rows-1);

    // auto buffer = getInputBuffer();
    // std::cout << buffer;
    // s_goToXY(buffer.size()+1, rows-1);
}
