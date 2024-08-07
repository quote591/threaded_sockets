
// Characters
const char wholeBlockChar = 219;
const char lowerBlockChar = 220;
const char upperBlockChar = 223;

class Display
{
public:

    // @brief Sets the terminal into raw mode that disables echo and line input
    static void s_setTerminalModeRaw(void);
    // @brief Resets the terminal mode to re-enable echo and line input
    static void s_setTerminalModeReset(void);

    // @brief returns the max coordinate in the console (zero indexed)
    // @args returns the value columns via ref
    // @args returns the value rows via ref
    static void s_getConsoleMaxCoords(short& columns, short& rows);

    // @brief Sets the cursor position in the terminal
    // @args x_col - set the x or column position
    // @args y_row - set the y or row position
    // @return bool if the oporation was sucessful
    static bool s_goToXY(const short x_col, const short y_row);

    // @brief clears the current terminal screen
    static void s_clearTerminal(void);

    // @brief draws the display
    static void s_draw(void);
};