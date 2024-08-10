#include "display.hpp"
#include "messageHandler.hpp"
#include "logging.hpp"

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

void Display::s_Draw(MessageHandler* messageHandlerHandle)
{
    std::lock_guard<std::mutex> lock(Display::s_writeToScreenMutex);

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

    // Draw previous messages
    auto displayMessages = messageHandlerHandle->m_GetDisplayMessages(rows-3);

    for (size_t i = 0; i < displayMessages.size(); i++)
    {
        s_GoToXY(1, rows-3-i);
        if (displayMessages[i].size() > columns-1)
        {
            std::cout << displayMessages[i].substr(0, columns-4);
            std::cout << "...";
        }
        else{
            std::cout << displayMessages[i];
        }

    }
    s_GoToXY(1, rows-1);
    std::cout << messageHandlerHandle->m_GetInputBufferStr();

    // After return cursor position to input box
    s_GoToXY(1+messageHandlerHandle->m_GetInputBufferSize(), rows-1);
}

void Display::s_WriteToScreen(short x_col, short y_row, std::string& msg)
{
    std::lock_guard<std::mutex> lock(Display::s_writeToScreenMutex);

    s_GoToXY(x_col, y_row);
    std::cout << msg;
}

void Display::s_WriteToInputDisplay(std::string msg)
{
    std::lock_guard<std::mutex> lock(Display::s_writeToScreenMutex);
    std::cout << msg;
}

void Display::s_WriteToInputDisplay(char c)
{
    std::lock_guard<std::mutex> lock(Display::s_writeToScreenMutex);
    std::cout << c;
}

void Display::s_ClearInputField(void)
{
    std::lock_guard<std::mutex> lock(Display::s_writeToScreenMutex);

    short columns, rows;
    Display::s_GetConsoleMaxCoords(columns, rows);

    // Put cursor at beginning to overwrite current text
    s_GoToXY(1, rows-1);

    std::string clearMsg = "";
    for (int i = 0; i < columns-2; i++)
        clearMsg += " ";
    std::cout << clearMsg;

    // Return cursor to the beginning of the input field
    s_GoToXY(1, rows-1);
}

void Display::s_DrawMessageDisplay(MessageHandler *messageHandlerHandle)
{
    std::lock_guard<std::mutex> lock(Display::s_writeToScreenMutex);
    
    short columns, rows;
    Display::s_GetConsoleMaxCoords(columns, rows);

    std::string clearString = "";
    for (int i = 0; i < columns-2; i++)
        clearString+=" ";

    for (int i = 1; i < rows-2; i++)
    {
        s_GoToXY(1, i);
        std::cout << clearString;
    }

    // Draw previous messages
    auto displayMessages = messageHandlerHandle->m_GetDisplayMessages(rows-3);

    for (size_t i = 0; i < displayMessages.size(); i++)
    {
        s_GoToXY(1, rows-3-i);
        if (displayMessages[i].size() > columns-1)
        {
            std::cout << displayMessages[i].substr(0, columns-4);
            std::cout << "...";
        }
        else{
            std::cout << displayMessages[i];
        }

    }
    s_GoToXY(1, rows-1);
    std::cout << messageHandlerHandle->m_GetInputBufferStr();

    // After return cursor position to input box
    s_GoToXY(1+messageHandlerHandle->m_GetInputBufferSize(), rows-1);
}
