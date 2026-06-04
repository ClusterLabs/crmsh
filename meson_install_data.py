#!/usr/bin/env python3
import os
import sys
import shutil

def main():
    if len(sys.argv) != 2:
        print("Usage: meson_install_data.py <datadir> ")
        sys.exit(os.EX_USAGE)

    datadir_opt = sys.argv[1]

    source_root = os.environ['MESON_SOURCE_ROOT']
    build_root = os.environ['MESON_BUILD_ROOT']
    destdir_prefix = os.environ['MESON_INSTALL_DESTDIR_PREFIX']
    target_datadir = os.path.join(destdir_prefix, datadir_opt, 'crmsh')

    print(f"Installing data-manifest files to {target_datadir}...")

    data_manifest_path = os.path.join(source_root, 'data-manifest')
    with open(data_manifest_path, 'r', encoding='utf-8') as f:
        files = [line.strip() for line in f if line.strip()]

    for d in files:
        src_path = os.path.join(build_root, d)
        if not os.access(src_path, os.F_OK | os.R_OK):
            src_path = os.path.join(source_root, d)
        if not os.access(src_path, os.F_OK | os.R_OK):
            print(f"Manifest file {src_path} does not exist.", file=sys.stderr)
            sys.exit(os.EX_NOINPUT)

        d_mapped = d
        if d.startswith('test/'):
            d_mapped = 'tests/' + d[5:]

        dest_path = os.path.join(target_datadir, d_mapped)
        print(f"Installing {src_path} to {dest_path}")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(src_path, dest_path)

        if os.access(src_path, os.X_OK):
            os.chmod(dest_path, 0o755)
        else:
            os.chmod(dest_path, 0o644)

    xmlonly_src = os.path.join(source_root, 'test', 'testcases', 'xmlonly.sh')
    if os.path.exists(xmlonly_src):
        filter_dest = os.path.join(target_datadir, 'tests', 'testcases', 'configbasic-xml.filter')
        print(f"Installing {xmlonly_src} to {filter_dest}")
        os.makedirs(os.path.dirname(filter_dest), exist_ok=True)
        shutil.copy2(xmlonly_src, filter_dest)
        os.chmod(filter_dest, 0o755)

if __name__ == '__main__':
    main()
