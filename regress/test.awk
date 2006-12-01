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

function failed(line) {
	failures++;
	print FILENAME ":" n ": FAILED: " line;
}
function passed(line) {
	print FILENAME ":" n ": PASSED: " line;
}

BEGIN {
	failures = 0;
	lines = "";
	n = 0;
	prefix = "(echo \'";
}

/.*/ {
	n++;
}

/^!.+/ {
	prefix = prefix substr($0, 2) "';echo '";
}

/^[^@!\#].+/ {
	if (lines != "") {
		lines = lines "'; echo '" $0;
	} else {
		lines = $0;
	}
	next;
}

/^@[0-9]( .*)?/ {
	rc = int(substr($0, 2, 1));
	re = substr($0, 4);

	cmd = prefix lines "')|" CMD " 2>&1";
	lines = "";

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
