// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal: the controlling side, which the test
// types into and reads the screen from, and the terminal itself, cols by
// rows.
func openPTY(cols, rows uint16) (ptm, tty *os.File, err error) {
	ptm, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(ptm.Fd())
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err == nil {
		err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0)
	}
	if err == nil {
		err = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: rows})
	}
	if err == nil {
		tty, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	}
	if err != nil {
		ptm.Close()
		return nil, nil, err
	}
	return ptm, tty, nil
}
