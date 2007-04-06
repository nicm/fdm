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

/^.*$/ {
	if ($0 ~ /^%%/) {
		name = substr($0, 3);
		while ((getline < name) == 1) {
			print ($0);
		}
		close(name);
	} else if ($0 ~ /^&&/) {
		name = substr($0, 3);
		while ((getline < name) == 1) {
			gsub("\<", "\\&lt;", $0);
			gsub("\>", "\\&gt;", $0);
			if ($0 ~ /^[0-9A-Za-z].+ ==+/) {
				gsub("==+$", "", $0);
				print ("<h1>" $0 "</h1>");
				getline < name;
				continue;
			}
			if ($0 ~ /^[0-9A-Za-z].+ --+/) {
				gsub("--+$", "", $0);
				print ("<h2>" $0 "</h2>");
				getline < name;
				continue;
			}
			print ($0);
		}
		close(name);
	} else {
		print ($0);
	}
}
