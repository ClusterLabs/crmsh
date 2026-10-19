#!/bin/bash
set -u

# Mount workspace drive
mkdir -p /opt/crmsh
if [ -b /dev/vdb ]; then
    mount /dev/vdb /opt/crmsh
fi

# Load cached haleap image if present
if [ -f /var/lib/haleap.tar ]; then
    if ! podman image exists localhost/haleap:latest 2>/dev/null; then
        echo "Loading cached localhost/haleap:latest container image..."
        podman load -i /var/lib/haleap.tar
        rm -f /var/lib/haleap.tar
    fi
fi


# Read arguments
ARGS=()
INTERACTIVE=0
if [ -f /opt/crmsh/.sandbox_args ]; then
    # Read args safely line-by-line to preserve spaces/quotes
    while IFS= read -r line; do
        ARGS+=("$line")
    done < /opt/crmsh/.sandbox_args
fi

# Check for interactive flag in arguments
CLEANED_ARGS=()
for arg in "${ARGS[@]}"; do
    if [ "$arg" = "-i" ] || [ "$arg" = "--interactive" ]; then
        INTERACTIVE=1
    else
        CLEANED_ARGS+=("$arg")
    fi
done

EXIT_CODE=0
if [ -x /opt/crmsh/test/run-functional-tests ]; then
    if [ ${#CLEANED_ARGS[@]} -gt 0 ]; then
        /opt/crmsh/test/run-functional-tests "${CLEANED_ARGS[@]}"
        EXIT_CODE=$?
    fi
else
    echo "ERROR: /opt/crmsh/test/run-functional-tests not found or not executable"
    EXIT_CODE=1
fi

if [ "$INTERACTIVE" -eq 1 ]; then
    echo "=========================================================="
    echo "Dropping into interactive sandbox shell (/opt/crmsh)."
    echo "Run 'exit' when finished to shutdown microVM."
    echo "=========================================================="
    cd /opt/crmsh
    bash --login -i < /dev/ttyS0 > /dev/ttyS0 2>&1
fi

# Record exit status for host
if [ -d /opt/crmsh ]; then
    echo "$EXIT_CODE" > /opt/crmsh/.sandbox_exit_status
    sync
fi

echo "crmsh sandbox finished with status $EXIT_CODE. Powering off..."
sync
# Trigger immediate reboot to signal firecracker to exit VM process.
reboot -f
