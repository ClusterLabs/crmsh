#!/bin/bash
crmtestout="$1"

[ -d "$crmtestout" ] || { echo "usage: $0 <test-output-dir>"; exit 1; }

for f in $crmtestout/*.diff; do
	fil=$(grep -- --- $f | awk '{print $2}' | sed 's/\/usr\/share\/crmsh\/tests/\/test/g')
	awk "NR==1{\$2=\"a$fil\"}1" < "$f" | awk "NR==2{\$2=\"b$fil\"}1"
done
