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
	print (FILENAME ":" line ": FAILED: " cmd);
}
function passed(cmd) {
	print (FILENAME ":" line ": PASSED: " cmd);
}

BEGIN {
	failures = 0;
	line = 0;

	nlines = 0;
	nheaders = 0;
	nmatches = 0;
}

/.*/ {
	line++;
}

/^!.+/ {
	headers[nheaders] = substr($0, 2);
	nheaders++;
	next;
}

/^[^@!\#].+/ {
	lines[nlines] = $0;
	nlines++;
	next;
}

/^@- .+/ {
	matches[nmatches] = substr($0, 4);
	nmatches++;
	next;
}

/^@[0-9]( .*)?/ {
	rc = int(substr($0, 2, 1));

	matches[nmatches] = substr($0, 4);
	if (matches[nmatches] != 0 && matches[nmatches] != "") {
		nmatches++;
	}

	cmd = "(echo '"
	for (i = 0; i < nheaders; i++) {
		cmd = cmd headers[i] "';echo '";
	}
	for (i = 0; i < nlines; i++) {
		if (i != nlines - 1) {
			cmd = cmd lines[i] "';echo '";
		} else {
			cmd = cmd lines[i];
		}
	}
	cmd = cmd "')|" CMD " 2>&1";

	for (i = 0; i < nmatches; i++) {
		found[i] = 0;
	}

	do {
		error = cmd | getline;
		if (error == -1) {
			break;
		}
		if (DEBUG != "") {
			print ("\t" $0);
		}
		for (i = 0; i < nmatches; i++) {
			if ($0 ~ matches[i]) {
				found[i] = 1;
			}
		}
	} while (error == 1);

	close(cmd);
	if (error == -1) {
		failed(cmd);
		next;
	}

	nlines = 0;

	nfound = 0;
	for (i = 0; i < nmatches; i++) {
		if (found[i] == 1) {
			nfound++;
		}
	}
	if (nfound != nmatches) {
		nmatches = 0;
		failed(cmd);
		next;
	}
	nmatches = 0;

	if (system(cmd " 2>/dev/null") != rc) {
		failed(cmd);
		next;
	}

	passed(cmd);
}

END {
	exit (failures);
}
