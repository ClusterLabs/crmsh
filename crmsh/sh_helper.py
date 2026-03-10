import argparse
import os
import pwd
import sys


def main():
    argument_parser = argparse.ArgumentParser(description="Helper script to run command in a clean environment")
    argument_parser.add_argument('--preserve-env', help="Environment variables to preserve, separated by comma")
    argument_parser.add_argument('command', help="Command to execute")
    args = argument_parser.parse_args()

    # Get user info for USER, LOGNAME, and HOME
    pw = pwd.getpwuid(os.getuid())
    user_name = pw.pw_name
    user_home = pw.pw_dir

    # Prepare a clean environment
    new_env = {}

    # 1. Keep TERM if it exists
    if 'TERM' in os.environ:
        new_env['TERM'] = os.environ['TERM']

    # 2. Keep SHELL if it was initialized by su (or previous environment)
    if 'SHELL' in os.environ:
        new_env['SHELL'] = os.environ['SHELL']

    # 3. Setup USER, LOGNAME and HOME
    new_env['USER'] = user_name
    new_env['LOGNAME'] = user_name
    new_env['HOME'] = user_home

    # Handle preserve_env
    if args.preserve_env:
        for var in args.preserve_env.split(','):
            var = var.strip()
            val = os.environ.get(var)
            if val is not None:
                new_env[var] = val

    # Default PATH if not preserved
    if 'PATH' not in new_env:
        # A sensible default path
        new_env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    
    # Change to user's home directory
    try:
        os.chdir(new_env['HOME'])
    except Exception as e:
        print(f"Warning: Could not change directory to {new_env['HOME']}: {e}", file=sys.stderr)
        sys.exit(1)

    # Replace the current process with /bin/bash -c <command>
    try:
        os.execve('/bin/bash', ['/bin/bash', '-c', args.command], new_env)
    except Exception as e:
        print(f"Failed to execute command: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
