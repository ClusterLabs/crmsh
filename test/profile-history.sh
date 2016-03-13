#!/bin/sh

case $1 in
	cumulative)
		python -c "import pstats; s = pstats.Stats(\"$2\"); s.sort_stats(\"cumulative\").print_stats()" | less
		;;
	time)
		python -c "import pstats; s = pstats.Stats(\"$2\"); s.sort_stats(\"time\").print_stats()" | less
		;;
	timecum)
		python -c "import pstats; s = pstats.Stats(\"$2\"); s.sort_stats(\"time\", \"cum\").print_stats()" | less
		;;
	callers)
		python -c "import pstats; s = pstats.Stats(\"$2\"); s.print_callers(.5, \"$3\")" | less
		;;
	verbose)
		PYTHONPATH=. ./crm -X "$2" -H "$3" history log
		;;
	*)
		PYTHONPATH=. ./crm -X "$1" -H "$2" history log >/dev/null
		;;
esac
