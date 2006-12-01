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

# This whole file is pretty crappy and fragile, but it does the job.

function convert() {
	n = 0;
	delete list;

	arg = 0;
	for (i = 2; i <= NF; i++) {
		arg++;

		type = rules[$i];
		if (type != 0 && types[type] != 0) {
			list[n] = "[$" arg  ": " $i " (" types[type] ")]";
			n++;
		}
	}

	return (n);
}

function pretty(initial, prefix, n) {
	s = initial;
	column = length(s);

	for (i = 0; i < n; i++) {
		if (column + length(list[i]) + 1 > 79) {
			column = 0;
			s = s "\n" prefix;
		}
		s = s list[i] " ";
		column += length(list[i]);
	}

	return (substr(s, 1, length(s) - 1));
}

function wspace(s, o) {
	gsub("\t", "        ", s);
	n = match(s, "[^ ]");
	
	n -= o;
	if (n < 0)
		n = 0;

	t = "";
	for (i = 0; i < n; i++) {
		t = t " ";
	}	

	return (t);
}

BEGIN {
	union = 0;
	name = ""
}

/^[ \t]*\/\*\*/ {
	next;
}

/^%union/ {
	print ($0);

	union = 1;
	next;

}

/^%type .+/ {
	print ($0);

	if (NF < 3)
		next;

	for (i = 3; i <= NF; i++) {
		rules[$i] = $2;
	}
	next;
}

/^[a-z]+: / {
	type = rules[substr($1, 1, length($1) - 1)];
	if (type != 0) {
		print ("/** " toupper($1) " " type " (" types[type] ") */");
	} else {
		print ("/** " toupper(substr($1, 1, length($1) - 1)) " */");
	}

	elements = convert();
	if (elements > 0) {
		s = ""
		for (i = 0; i < length($1) - 4; i++) {
			s = " " s;
		}
		print ("/**" pretty(s ": ", "     " s, elements) " */");
	}

	print ($0);
	next;
}

/^[ \t]*\| / {
	elements = convert();
	if (elements > 0) {
		s = wspace($0, 4);
		print ("/**" pretty(s "| ", "     " s, elements) " */");
	}

	print ($0);
	next;	
}

/.*/ {
 	print ($0);

	if (union == 2) {
		if (NF == 2 && $1 == "}") {
			union = 1;

			name = $NF;
			if (substr(name, 1, 1) == "*") {
				type = type " *";
				name = substr(name, 2);
			}
			name = substr(name, 1, length(name) - 1);

			types["<" name ">"] = type "... } " name;
			next;
		}

		# Include struct members.
		#for (i = 1; i <= NF; i++) {
		#	type = type $i " ";
		#}
	}

	if (union == 1) {
		if ($1 == "}") {
			union = 0;
			next;
		}

		if (NF == 2 && $NF == "{") {
			type = $(NF - 1) " { ";
			union = 2;
			next;
		}

		type = ""
		for (i = 1; i < NF; i++) {
			type = type $i " ";
		}
		type = substr(type, 1, length(type) - 1);

		name = $NF;
		if (substr(name, 1, 1) == "*") {
			type = type " *";
			name = substr(name, 2);
		}
		name = "<" substr(name, 1, length(name) - 1) ">";

		types[name] = type;
		next;
	}
}
