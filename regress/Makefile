# $Id$

TEST= account.test

CMD= ../fdm -vvnf /dev/stdin

.for n in ${TEST}
TARGETS+= ${n}
${n}:
		@echo ${n}:
		@awk ' \
			function failed(line) {				\
				failures++;				\
				print "FAILED: " line;			\
			}						\
			function passed(line) {				\
				print "PASSED: " line;			\
			}						\
									\
			BEGIN {						\
				failures = 0;				\
				line = "";				\
			}						\
									\
			/^[^@#].+/ {					\
				line = $$0;				\
				next;					\
			}						\
									\
			/^@[0-9]( .*)?/ {				\
				rc = int(substr($$0, 2, 1)); 		\
				re = substr($$0, 4);			\
									\
				gsub("\"", "\\\"", line);		\
				cmd = "echo \"" line "\"|${CMD} 2>&1";	\
									\
				found = 0;				\
				do {					\
					error = cmd | getline;		\
					if (error == -1) {		\
						break;			\
					}				\
					if (re != "" && $$0 ~ re) {	\
						found = 1;		\
					}				\
				} while (error == 1);			\
									\
				close(cmd);				\
									\
				if (!found || error == -1) {		\
					failed(line);			\
					next;				\
				} 					\
				if (system(cmd " 2>/dev/null") != rc) {	\
					failed(line);			\
					next;				\
				}					\
				passed(line);				\
			}						\
			END {						\
				exit(failures);				\
			}' ${n}	
.endfor

.PHONY: regress ${TARGETS}

regress:	${TARGETS}
