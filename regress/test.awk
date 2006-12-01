# $Id$
#
# Copyright (c) 2006 Nicholas Marriott <nicm@users.sourceforge.net>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
# IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

function failed(cmd) {
	failures++;
	print FILENAME ":" n ": FAILED: " cmd;
}
function passed(cmd) {
	print FILENAME ":" n ": PASSED: " cmd;
}

BEGIN {
	failures = 0;
	n = 0;

	line = 0;
	header = 0;
}

/.*/ {
	n++;
}

/^!.+/ {
	headers[header] = substr($0, 2);
	header++;
	next;
}

/^[^@!\#].+/ {
	lines[line] = $0;
	line++;
	next;
}

/^@[0-9]( .*)?/ {
	rc = int(substr($0, 2, 1));
	re = substr($0, 4);

	cmd = "(echo '"
	for (i = 0; i < header; i++) {
		cmd = cmd headers[i] "';echo '";
	}
	for (i = 0; i < line; i++) {
		if (i != line - 1) {
			cmd = cmd lines[i] "';echo '";
		} else {
			cmd = cmd lines[i];
		}
	}
	cmd = cmd "')|" CMD " 2>&1";
	line = 0;

	found = 0;
	do {
		error = cmd | getline;
		if (DEBUG) {
			print ("\t" $0);
		}
		if (error == -1) {
			break;
		}
		if (re != 0 && $0 ~ re) {
			found = 1;
		}
	} while (error == 1);

	close(cmd);

	if (!found || error == -1) {
		failed(cmd);
		next;
	}
	if (system(cmd " 2>/dev/null") != rc) {
		failed(cmd);
		next;
	}
	passed(cmd);
}

END {
	exit (failures);
}
