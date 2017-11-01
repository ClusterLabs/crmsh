#!/bin/sh
docker pull krig/crmsh:latest
docker run -t -v "$(pwd):/app" krig/crmsh /bin/sh -c "systemctl start dbus; cd /app; ./test/run-in-container.sh $(whoami) $(id -u) $(id -g)"
