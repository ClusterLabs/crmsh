#!/bin/bash
crmtestout="$1"

for f in $crmtestout/*.diff; do
	fil=$(grep -- --- $f | awk '{print $2}' | sed 's/\/usr\/share\/crmsh\/tests/\/test/g')

	cat $f | awk "NR==1{\$2=\"a$fil\"}1" | awk "NR==2{\$2=\"b$fil\"}1"


done
