#!/usr/bin/env python3
"""Compare an uninstalled candidate's application ID to Android 13's service.

Requires a rooted Android 13 device and a remote dex/jar classpath containing
the unminified candidate, its runtime dependencies and the Java probe.
Only reads package metadata: no key generation or Play Integrity requests.
"""
import argparse
import base64
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--classpath', required=True, help='Already staged device dex/jar paths')
    parser.add_argument('--uid', type=int, action='append', required=True)
    args = parser.parse_args()
    adb = ['adb', '-s', args.serial]
    sdk = subprocess.check_output(adb + ['shell', 'getprop', 'ro.build.version.sdk'], text=True).strip()
    if sdk != '33':
        parser.error('This probe targets the Android 13 provider API')
    for uid in args.uid:
        results = {}
        for mode in ['canonical', 'candidate']:
            command = ('CLASSPATH=' + shlex.quote(args.classpath) +
                       ' app_process /system/bin ApplicationIdConformanceProbe ' +
                       mode + ' ' + str(uid))
            output = subprocess.check_output(
                adb + ['shell', 'su 1017 -c ' + shlex.quote(command)],
                text=True, timeout=30)
            rows = [line.split('|', 1)[1] for line in output.splitlines()
                    if line.startswith('APPLICATION_ID_DER|')]
            if len(rows) != 1:
                raise RuntimeError(f'{mode}: expected exactly one application ID')
            results[mode] = base64.b64decode(rows[0], validate=True)
        if results['canonical'] != results['candidate']:
            raise RuntimeError(f'UID {uid}: candidate differs from framework application ID')
        print(f'UID {uid}: candidate matches framework application ID ({len(results["candidate"])} DER bytes)')


if __name__ == '__main__':
    main()
