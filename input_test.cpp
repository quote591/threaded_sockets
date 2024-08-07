#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <sstream>

#include <windows.h>
#include <conio.h>

std::atomic<int> threadReturn(0); // Flag that instructs all other threads to cleanup and terminate
std::atomic<int> updateDraw(0); // Flag that instructs draw thread to update the screen

std::vector<char> inputBuffer;
std::mutex inputBufferMutex;

// Buffer above the input area. Each vector contains the message string
std::vector<std::string> chatBuffer;

// Characters
const char wholeBlockChar = 219;
const char lowerBlockChar = 220;
const char upperBlockChar = 223;

std::ostream& operator<<(std::ostream& os, const std::vector<char>& vec)
{
    for (char c : vec)
        os << c;
    return os;
}

void pushInputBuffer(char c)
{
    std::lock_guard<std::mutex> lock(inputBufferMutex);
    inputBuffer.push_back(c);
}

void deleteLastCharacter(void)
{
    std::lock_guard<std::mutex> lock(inputBufferMutex);
    inputBuffer.pop_back();
}

// Copy return
std::vector<char> getInputBuffer(void)
{
    std::lock_guard<std::mutex> lock(inputBufferMutex);
    return inputBuffer;
}

// (Windows only)
// https://cplusplus.com/forum/beginner/23421/
bool GoToXY(short int x, short int y )
{
    COORD position = { x, y };
    return SetConsoleCursorPosition( GetStdHandle( STD_OUTPUT_HANDLE ), position );
}

// This adds the buffer to the display
void addMessageToDisplay(std::vector<char>& message, const short cols, const short rows)
{
    std::stringstream ss;
    GoToXY(1, rows-3);

    // Create string from the chars
    for (char c : inputBuffer)
        ss << c;

    std::cout << ss.str();
}




// Zero indexed
void GetConsoleMaxCoord(int& columns, int& rows)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    columns = csbi.srWindow.Right - csbi.srWindow.Left;
    rows = csbi.srWindow.Bottom - csbi.srWindow.Top;
}

void DrawBorder(void)
{
    const char boxDrawingChar = 0xDB;
    int columns, rows;
    GetConsoleMaxCoord(columns, rows);

    for (int i = 1; i < columns; i++)
    {
        GoToXY(i, 0);
        std::cout << wholeBlockChar;
        GoToXY(i, rows-2);
        std::cout << upperBlockChar; 
        GoToXY(i, rows);
        std::cout << lowerBlockChar;
    }
    // Top and bottom corners already done
    for (int i = 0; i < rows+1; i++)
    {
        GoToXY(0, i);
        std::cout << wholeBlockChar;
        GoToXY(columns, i);
        std::cout << wholeBlockChar;
    }
    // Position of the input part
    GoToXY(1,rows-1);

    auto buffer = getInputBuffer();
    std::cout << buffer;
    GoToXY(buffer.size()+1, rows-1);
}

void DrawDimensions(int col, int row)
{
    GoToXY(col/=2, row/=2);
    std::cout << col << "x" << row << std::endl;
}

// Stop the terminal from echoing everything out
void setRawMode() {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hInput, &mode);
    mode &= ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(hInput, mode);
}

// reset terminal
void resetMode() {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hInput, &mode);
    mode |= (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(hInput, mode);
}

int main()
{
    system("cls"); // Windows only clear terminal

    // std::srand(std::time(nullptr));
    // std::thread printThread([&]{
    //     while(true)
    //     {
    //         auto value = std::chrono::milliseconds(std::rand() % 2000);
    //         std::this_thread::sleep_for(value);
    //         std::cout << "Test message. (" << value.count() << ")" << std::endl;

    //         if (threadReturn)
    //             break;
    //     }
    // });

    std::thread drawThread([]{
        DrawBorder(); // Inital draw
        int oldColumn, oldRow;
        GetConsoleMaxCoord(oldColumn, oldRow);
        while (true)
        {
            int column, row;
            GetConsoleMaxCoord(column, row);
            if (oldColumn != column || oldRow != row || updateDraw)
            {
                system("cls"); // Windows only
                DrawBorder();
                oldColumn = column; oldRow = row;
                updateDraw^=1;
            }
                
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (threadReturn) {return;}
        }
    });

    // int columns, rows;
    // GetConsoleMaxCoord(columns, rows);
    setRawMode();



    // Might not need
    // SetConsoleOutputCP(437);

    // Minimum size 50x10

    // Code page 437
    // https://en.wikipedia.org/wiki/Code_page_437 (hover over ALT+N) N is the number we use
    // char boxDrawingChar = 0xDB;  // Full block character in Code page 437
    // std::cout << "Box drawing character (full block): " << boxDrawingChar << std::endl;

    char c;
    while (true) {
        if (_kbhit()) {  // Check if a key is pressed
            c = _getch();  // Read the key press without buffering (no await enter key)
            if (c == '\r' || c == '\n') { 
                // std::cout << "Enter key pressed." << std::endl;
                int column, row;
                GetConsoleMaxCoord(column, row);
                addMessageToDisplay(inputBuffer, column, row);
                // Here we can do checks like is input "Exit", then we return.
                // break;
            }
            else if(c == 27) // ASCII ESC
            {
                break;
            }
            // If char is printable then we can add it to our buffer
            if (std::isprint(c))
            {
                pushInputBuffer(c);
                std::cout << c;
            }
            else if (c == 8 && inputBuffer.size() != 0) // backspace
            {
                deleteLastCharacter();
                std::cout << "\b \b";
            }
        }
        // Small delay to avoid the heavy load
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }

    resetMode();

    // Switch polarity (exit thread)
    threadReturn^=1;
    // printThread.join();
    drawThread.join();

    return 0;
}
