#!/bin/sh
docker pull krig/crmsh:latest

if [ "$1" = "--unit-tests" ]; then
	docker run -t -v "$(pwd):/app" krig/crmsh /bin/sh -c "cd /app; ./test/unit-tests-in-container.sh $(id -un) $(id -gn) $(id -u) $(id -g)"
else
	docker run -t -v "$(pwd):/app" krig/crmsh /bin/sh -c "cd /app; ./test/run-in-container.sh $(id -un) $(id -gn) $(id -u) $(id -g)"
fi
