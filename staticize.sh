#!/bin/bash
set -e
outdir="$1"
infile="$2"
exename="$(basename "$infile")"

rm -rf "$outdir"
mkdir "$outdir"
cp -a "$infile" "$outdir/$exename"
install_name_tool -add_rpath /Library/Developer/CommandLineTools/usr/lib/ "$outdir/$exename"
mod=1
while [ "$mod" = "1" ]; do
	mod=0
	for dependor in "$outdir"/*; do
		otool -L "$dependor" | fgrep -q /stage || continue
		mod=1
		for dependee in `otool -L "$dependor" | fgrep /stage | awk '{print $1}'`; do
			d="$(basename "$dependee")"
			cp -n "/usr/local/lib/$d" "$outdir/"
			install_name_tool -id "$d" "$outdir/$d"
			install_name_tool -change "$dependee" "$(echo "$dependee" | sed 's!.*lib/!@loader_path/!')" "$dependor"
		done
	done
done
