# Copyright (c) 2024 Guido Borst
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import curses

def draw_menu(stdscr, current_index, options, counters, menu_text, bool_input):
    stdscr.clear()
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)

    stdscr.addstr(0, 0, menu_text)
    height, width = stdscr.getmaxyx()

    # Dynamically calculate max_options_displayed based on the available space
    # Reserve 4 lines for instructions and potential 'more items' indicators
    max_options_displayed = height - 4

    # Calculate the middle position for the highlighted item
    middle_option_index = max_options_displayed // 2 - 1

    # Adjust start_index to try to keep the current selection in the middle
    start_index = max(0, min(current_index - middle_option_index, len(options) - max_options_displayed + 1))
    end_index = min(start_index + max_options_displayed - 2, len(options))

    # Adjust the display to include indicators as part of the list items
    display_indices = range(max(0, start_index), min(len(options), end_index + 1))

    display_start_line = 2
    if start_index > 0:
        stdscr.addstr(display_start_line, 0, '↑ More items above', curses.A_DIM)

    for i, display_index in enumerate(display_indices, start=display_start_line):
        if display_index == start_index and start_index > 0:
            # Skip the first loop iteration if the first item is an indicator to avoid extra white line
            continue
        elif display_index == end_index and end_index < len(options) - 1:
            # Indicator for more items below
            stdscr.addstr(i, 0, '↓ More items below', curses.A_DIM)
            break
        else:
            option = options[display_index]
            if bool_input:
                counter_str = '(*)' if counters[display_index] > 0 else '( )'
            else:
                counter_str = str(counters[display_index])
            if display_index == current_index:
                stdscr.attron(curses.color_pair(2))
                stdscr.addstr(i, 0, f'{counter_str} {option}')
                stdscr.attroff(curses.color_pair(2))
            else:
                stdscr.addstr(i, 0, f'{counter_str} {option}')

    stdscr.addstr(height - 2, 0, 'Use the cursor keys to navigate the menu and Space to select options')
    stdscr.addstr(height - 1, 0, 'Press Enter to confirm your selection or Q to quit')

    stdscr.refresh()


def main(stdscr, options, counters=None, menu_text='Select options using Space, move selection using the cursor keys:', bool_input=False):
    if counters is None:
        counters = [0]*len(options)
    curses.cbreak()
    stdscr.keypad(True)
    current_index = 0
    draw_menu(stdscr, current_index, options, counters, menu_text, bool_input)

    while True:
        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_index = max(0, current_index - 1)
        elif key == curses.KEY_DOWN:
            current_index = min(len(options) - 1, current_index + 1)
        elif key == curses.KEY_RIGHT and not bool_input:
            counters[current_index] += 1
        elif key == curses.KEY_LEFT and not bool_input:
            counters[current_index] = max(0, counters[current_index] - 1)
        elif key == ord(' ') and bool_input:
            counters[current_index] = 1 if counters[current_index] == 0 else 0
        elif key == ord('Q') or key == ord('q'):
            break
        elif (key == curses.KEY_ENTER or key in [10, 13]) and any(counters):
            break

        draw_menu(stdscr, current_index, options, counters, menu_text, bool_input)

    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    # curses.endwin()

    return counters

def make_menu_selection(options:list[str], counters:list[int]=None, menu_text='Select options:', print_results=False, bool_input=False, return_as_str=False):
    """
    Displays a menu with the given options and allows the user to make selections.

    Args:
        options (list[str]): A list of options to display in the menu.
        counters (list[int], optional): A list of pre-set counters for each option. Defaults to None.
        menu_text (str, optional): The text to display as the menu header. Defaults to 'Select options:'.
        print_results (bool, optional): Whether to print the selected options and their counters. Defaults to False.
        bool_input (bool, optional): Whether to use boolean input (Y/N) instead of numeric input. Defaults to False.
        return_as_str (bool, optional): Whether to return the selected options as strings instead of counters. Defaults to False.

    Returns:
        list[int] or list[str]: A list of counters for each option, or a list of selected options as strings if return_as_str is True.

    """
    counters = curses.wrapper(main, options, counters, menu_text, bool_input)
    if print_results:
        for i, option in enumerate(options):
            print(f'{option}: {counters[i]}')
    if return_as_str:
        return [option for i, option in enumerate(options) if counters[i] > 0]
    return counters
    

if __name__ == "__main__":
    options = ['Option A', 'Option B', 'Option C', 'Option D']
    counters = make_menu_selection(options, print_results=True, bool_input=True)

