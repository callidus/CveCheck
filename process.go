package main

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
  "fmt"
)

type Token int

const (
	ILLEGAL Token = iota
	EOF
	WS
	IDENT
	LESS_THAN_EQ
	LESS_THAN
	MORE_THAN
	MORE_THAN_EQ
	EQUAL
	NOT_EQ
	COMMA
	COMMENT
	VERSION
)

func isWhitespace(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\n'
}

func isLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isNumber(ch rune) bool {
	return (ch >= '0' && ch <= '9') || ch == '.'
}

type Scanner struct {
	r *bufio.Reader
}

func NewScanner(r io.Reader) *Scanner {
	return &Scanner{r: bufio.NewReader(r)}
}

var eof = rune(0)

func (s *Scanner) read() rune {
	ch, _, err := s.r.ReadRune()
	if err != nil {
		return eof
	}
	return ch
}

func (s *Scanner) unread() {
	_ = s.r.UnreadRune()
}

func (s *Scanner) scanComment() string {
	var buf bytes.Buffer
	for ch := s.read(); (ch != rune('\n') && ch != eof); {
		buf.WriteRune(ch)
    ch = s.read()
	}
	return buf.String()
}

func (s *Scanner) scanIdent() string {
	var buf bytes.Buffer
	for ch := s.read(); isLetter(ch); {
		buf.WriteRune(ch)
    ch = s.read()
	}
	s.unread()
	return buf.String()
}

func (s *Scanner) scanNumber() string {
	var buf bytes.Buffer
	for ch := s.read(); isNumber(ch); {
		buf.WriteRune(ch)
    ch = s.read()
	}
	s.unread()
	return buf.String()
}

func (s *Scanner) Scan() (tok Token, lit string) {
	ch := rune(0)
	for ch = s.read(); isWhitespace(ch); {
    ch = s.read()
	}

	if isLetter(ch) {
		s.unread()
		return IDENT, s.scanIdent()
	}

  if isNumber(ch) {
    s.unread()
    return VERSION, s.scanNumber()
  }

	switch ch {
	case eof:
		return EOF, ""

	case '>':
		if s.read() == '=' {
			return MORE_THAN_EQ, ">="
		} else {
			s.unread()
			return MORE_THAN, ">"
		}

	case '<':
		if s.read() == '=' {
			return LESS_THAN_EQ, "<="
		} else {
			s.unread()
			return LESS_THAN, "<"
		}

	case '=':
		if s.read() == '=' {
			return EQUAL, "=="
		} else {
			s.unread()
		}

	case '!':
		if s.read() == '=' {
			return NOT_EQ, "!="
		} else {
			s.unread()
		}

	case ',':
		return COMMA, ","

	case '#':
		comment := s.scanComment()
		return COMMENT, comment
	}

	return ILLEGAL, string(ch)
}

func main() {
	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

  s := NewScanner(file)
  for tok, val := s.Scan(); tok != EOF; tok, val = s.Scan(){
    fmt.Println(val)
  }
}
