#include <mutex>

// Characters
const char wholeBlockChar = 219;
const char lowerBlockChar = 220;
const char upperBlockChar = 223;

class Display
{
private:
    // @brief Sets the cursor position in the terminal
    // @args x_col - set the x or column position
    // @args y_row - set the y or row position
    // @return bool if the oporation was sucessful
    static bool s_GoToXY(const short x_col, const short y_row);
public:
    static std::mutex s_writeToScreenMutex; // For drawing to screen via iostream

    // @brief Sets the terminal into raw mode that disables echo and line input
    static void s_SetTerminalModeRaw(void);
    // @brief Resets the terminal mode to re-enable echo and line input
    static void s_SetTerminalModeReset(void);

    // @brief returns the max coordinate in the console (zero indexed)
    // @args returns the value columns via ref
    // @args returns the value rows via ref
    static void s_GetConsoleMaxCoords(short& columns, short& rows);

    // @brief clears the current terminal screen
    static void s_ClearTerminal(void);

    // @brief draws the display
    static void s_Draw(std::mutex& writeToScreenMutex);

    // @brief Thread safe way to access std::cout
    // @args Mutex for screen writing
    // @args X position on screen
    // @args Y position on screen
    // @args msg - string reference to the message
    static void s_WriteToScreen(std::mutex writeToScreenMutex, short x_col, short y_row, std::string& msg);
};
