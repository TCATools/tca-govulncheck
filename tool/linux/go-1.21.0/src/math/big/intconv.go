// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements int-to-string conversion functions.

package big

import (
	"errors"
	"fmt"
	"io"
)

// Text returns the string representation of x in the given base.
// Base must be between 2 and 62, inclusive. The result uses the
// lower-case letters 'a' to 'z' for digit values 10 to 35, and
// the upper-case letters 'A' to 'Z' for digit values 36 to 61.
// No prefix (such as "0x") is added to the string. If x is a nil
// pointer it returns "<nil>".
func (x *Int) Text(base int) string {
	if x == nil {
		return "<nil>"
	}
	return string(x.abs.itoa(x.neg, base))
}

// Append appends the string representation of x, as generated by
// x.Text(base), to buf and returns the extended buffer.
func (x *Int) Append(buf []byte, base int) []byte {
	if x == nil {
		return append(buf, "<nil>"...)
	}
	return append(buf, x.abs.itoa(x.neg, base)...)
}

// String returns the decimal representation of x as generated by
// x.Text(10).
func (x *Int) String() string {
	return x.Text(10)
}

// write count copies of text to s.
func writeMultiple(s fmt.State, text string, count int) {
	if len(text) > 0 {
		b := []byte(text)
		for ; count > 0; count-- {
			s.Write(b)
		}
	}
}

var _ fmt.Formatter = intOne // *Int must implement fmt.Formatter

// Format implements fmt.Formatter. It accepts the formats
// 'b' (binary), 'o' (octal with 0 prefix), 'O' (octal with 0o prefix),
// 'd' (decimal), 'x' (lowercase hexadecimal), and
// 'X' (uppercase hexadecimal).
// Also supported are the full suite of package fmt's format
// flags for integral types, including '+' and ' ' for sign
// control, '#' for leading zero in octal and for hexadecimal,
// a leading "0x" or "0X" for "%#x" and "%#X" respectively,
// specification of minimum digits precision, output field
// width, space or zero padding, and '-' for left or right
// justification.
func (x *Int) Format(s fmt.State, ch rune) {
	// determine base
	var base int
	switch ch {
	case 'b':
		base = 2
	case 'o', 'O':
		base = 8
	case 'd', 's', 'v':
		base = 10
	case 'x', 'X':
		base = 16
	default:
		// unknown format
		fmt.Fprintf(s, "%%!%c(big.Int=%s)", ch, x.String())
		return
	}

	if x == nil {
		fmt.Fprint(s, "<nil>")
		return
	}

	// determine sign character
	sign := ""
	switch {
	case x.neg:
		sign = "-"
	case s.Flag('+'): // supersedes ' ' when both specified
		sign = "+"
	case s.Flag(' '):
		sign = " "
	}

	// determine prefix characters for indicating output base
	prefix := ""
	if s.Flag('#') {
		switch ch {
		case 'b': // binary
			prefix = "0b"
		case 'o': // octal
			prefix = "0"
		case 'x': // hexadecimal
			prefix = "0x"
		case 'X':
			prefix = "0X"
		}
	}
	if ch == 'O' {
		prefix = "0o"
	}

	digits := x.abs.utoa(base)
	if ch == 'X' {
		// faster than bytes.ToUpper
		for i, d := range digits {
			if 'a' <= d && d <= 'z' {
				digits[i] = 'A' + (d - 'a')
			}
		}
	}

	// number of characters for the three classes of number padding
	var left int  // space characters to left of digits for right justification ("%8d")
	var zeros int // zero characters (actually cs[0]) as left-most digits ("%.8d")
	var right int // space characters to right of digits for left justification ("%-8d")

	// determine number padding from precision: the least number of digits to output
	precision, precisionSet := s.Precision()
	if precisionSet {
		switch {
		case len(digits) < precision:
			zeros = precision - len(digits) // count of zero padding
		case len(digits) == 1 && digits[0] == '0' && precision == 0:
			return // print nothing if zero value (x == 0) and zero precision ("." or ".0")
		}
	}

	// determine field pad from width: the least number of characters to output
	length := len(sign) + len(prefix) + zeros + len(digits)
	if width, widthSet := s.Width(); widthSet && length < width { // pad as specified
		switch d := width - length; {
		case s.Flag('-'):
			// pad on the right with spaces; supersedes '0' when both specified
			right = d
		case s.Flag('0') && !precisionSet:
			// pad with zeros unless precision also specified
			zeros = d
		default:
			// pad on the left with spaces
			left = d
		}
	}

	// print number as [left pad][sign][prefix][zero pad][digits][right pad]
	writeMultiple(s, " ", left)
	writeMultiple(s, sign, 1)
	writeMultiple(s, prefix, 1)
	writeMultiple(s, "0", zeros)
	s.Write(digits)
	writeMultiple(s, " ", right)
}

// scan sets z to the integer value corresponding to the longest possible prefix
// read from r representing a signed integer number in a given conversion base.
// It returns z, the actual conversion base used, and an error, if any. In the
// error case, the value of z is undefined but the returned value is nil. The
// syntax follows the syntax of integer literals in Go.
//
// The base argument must be 0 or a value from 2 through MaxBase. If the base
// is 0, the string prefix determines the actual conversion base. A prefix of
// “0b” or “0B” selects base 2; a “0”, “0o”, or “0O” prefix selects
// base 8, and a “0x” or “0X” prefix selects base 16. Otherwise the selected
// base is 10.
func (z *Int) scan(r io.ByteScanner, base int) (*Int, int, error) {
	// determine sign
	neg, err := scanSign(r)
	if err != nil {
		return nil, 0, err
	}

	// determine mantissa
	z.abs, base, _, err = z.abs.scan(r, base, false)
	if err != nil {
		return nil, base, err
	}
	z.neg = len(z.abs) > 0 && neg // 0 has no sign

	return z, base, nil
}

func scanSign(r io.ByteScanner) (neg bool, err error) {
	var ch byte
	if ch, err = r.ReadByte(); err != nil {
		return false, err
	}
	switch ch {
	case '-':
		neg = true
	case '+':
		// nothing to do
	default:
		r.UnreadByte()
	}
	return
}

// byteReader is a local wrapper around fmt.ScanState;
// it implements the ByteReader interface.
type byteReader struct {
	fmt.ScanState
}

func (r byteReader) ReadByte() (byte, error) {
	ch, size, err := r.ReadRune()
	if size != 1 && err == nil {
		err = fmt.Errorf("invalid rune %#U", ch)
	}
	return byte(ch), err
}

func (r byteReader) UnreadByte() error {
	return r.UnreadRune()
}

var _ fmt.Scanner = intOne // *Int must implement fmt.Scanner

// Scan is a support routine for fmt.Scanner; it sets z to the value of
// the scanned number. It accepts the formats 'b' (binary), 'o' (octal),
// 'd' (decimal), 'x' (lowercase hexadecimal), and 'X' (uppercase hexadecimal).
func (z *Int) Scan(s fmt.ScanState, ch rune) error {
	s.SkipSpace() // skip leading space characters
	base := 0
	switch ch {
	case 'b':
		base = 2
	case 'o':
		base = 8
	case 'd':
		base = 10
	case 'x', 'X':
		base = 16
	case 's', 'v':
		// let scan determine the base
	default:
		return errors.New("Int.Scan: invalid verb")
	}
	_, _, err := z.scan(byteReader{s}, base)
	return err
}
