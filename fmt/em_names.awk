/^#define\s+EM_.*\s+[0-9]+/ { names[$3] = $2 }
END { for(i=0; i<=94; i++) { a = a "\"" (names[i] ? tolower(substr(names[i], 4)) : ("unk_" i)) "\", " } print a }
