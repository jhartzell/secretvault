package application

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

type promptOption struct {
	Value       string
	Label       string
	Description string
}

func isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func promptSelect(title string, options []promptOption) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("no options available")
	}

	if !isInteractiveTerminal() {
		return options[0].Value, nil
	}

	fmt.Println(title)
	for i, option := range options {
		if strings.TrimSpace(option.Description) == "" {
			fmt.Printf("%d) %s\n", i+1, option.Label)
			continue
		}
		fmt.Printf("%d) %s - %s\n", i+1, option.Label, option.Description)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Select option [1-%d] (default 1): ", len(options))
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return options[0].Value, nil
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 1 || idx > len(options) {
			fmt.Println("Invalid selection.")
			continue
		}
		return options[idx-1].Value, nil
	}
}

func promptInput(label, defaultValue string) (string, error) {
	if !isInteractiveTerminal() {
		return strings.TrimSpace(defaultValue), nil
	}

	reader := bufio.NewReader(os.Stdin)
	prompt := label
	if strings.TrimSpace(defaultValue) != "" {
		prompt = fmt.Sprintf("%s [%s]", label, defaultValue)
	}
	fmt.Printf("%s: ", prompt)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return strings.TrimSpace(defaultValue), nil
	}
	return line, nil
}

func promptMultiSelect(title string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	if !isInteractiveTerminal() {
		out := make([]string, len(values))
		copy(out, values)
		return out, nil
	}

	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer func() { _ = term.Restore(fd, state) }()

	fmt.Print("\x1b[?25l")
	defer fmt.Print("\x1b[?25h")

	selected := make([]bool, len(values))
	for i := range selected {
		selected[i] = true
	}

	reader := bufio.NewReader(os.Stdin)
	cursor := 0
	renderedLines := 0
	for {
		renderedLines = renderMultiSelect(title, values, selected, cursor, renderedLines)

		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}

		switch b {
		case '\r', '\n':
			fmt.Print("\r\n")
			return collectSelectedValues(values, selected), nil
		case ' ':
			selected[cursor] = !selected[cursor]
		case 'j':
			if cursor < len(values)-1 {
				cursor++
			}
		case 'k':
			if cursor > 0 {
				cursor--
			}
		case 'a':
			for i := range selected {
				selected[i] = true
			}
		case 'n':
			for i := range selected {
				selected[i] = false
			}
		case 'q', 3:
			fmt.Print("\r\n")
			return nil, errors.New("selection cancelled")
		case 27:
			next, err := reader.ReadByte()
			if err != nil {
				return nil, err
			}
			if next != '[' {
				continue
			}
			arrow, err := reader.ReadByte()
			if err != nil {
				return nil, err
			}
			switch arrow {
			case 'A':
				if cursor > 0 {
					cursor--
				}
			case 'B':
				if cursor < len(values)-1 {
					cursor++
				}
			}
		}
	}
}

func renderMultiSelect(title string, values []string, selected []bool, cursor int, previousLines int) int {
	if previousLines > 0 {
		fmt.Printf("\x1b[%dA", previousLines)
	}

	lineCount := 0
	fmt.Printf("\r\x1b[2K%s\n", title)
	lineCount++
	fmt.Printf("\r\x1b[2K%s\n", "Use arrow keys to move, space to toggle, a=all, n=none, enter=continue")
	lineCount++

	for i, value := range values {
		pointer := " "
		if i == cursor {
			pointer = ">"
		}
		mark := "[ ]"
		if selected[i] {
			mark = "[x]"
		}
		fmt.Printf("\r\x1b[2K%s %s %s\n", pointer, mark, value)
		lineCount++
	}

	return lineCount
}

func collectSelectedValues(values []string, selected []bool) []string {
	if len(values) != len(selected) {
		return nil
	}
	out := make([]string, 0, len(values))
	for i := range values {
		if selected[i] {
			out = append(out, values[i])
		}
	}
	return out
}
