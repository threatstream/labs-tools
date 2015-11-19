#!/usr/bin/python
#
# Copyright (C) 2015 THREATSTREAM, Inc.
# This file is subject to the terms and conditions of the GNU General Public
# License version 2.  
import re
import sys
import zlib
import subprocess
from pydoc import pager
try:
    from PyInstaller.utils.cliutils import archive_viewer
except ImportError:
    print('You must install PyInstaller >= 3.0 first. Hint: pip install PyInstaller')
    exit()
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


__author__ = 'ThreatStream Labs'
__desc__ = 'Quickly extract Python Scripts from PyInstaller compiled binaries.'
__yara__ = '''
rule PyInstaller_Binary
{
meta:
    author = "ThreatStream Labs"
    desc = "Generic rule to identify PyInstaller Compiled Binaries"
strings:
    $string0 = "zout00-PYZ.pyz"
    $string1 = "python"
    $string2 = "Python DLL"
    $string3 = "Py_OptimizeFlag"
    $string4 = "pyi_carchive"
    $string5 = ".manifest"
    $magic = { 00 4d 45 49 0c 0b 0a 0b 0e 00 }
condition:
        all of them // and new_file
}
'''
normal_stdout = sys.stdout


def redirect_stdout():
    '''Simply pulls in STDOUT so we can use PyInstallers tool instead of reinventing the wheel'''
    if sys.stdout is normal_stdout:
        sys.stdout = StringIO()
        return
    sys.stdout.seek(0)
    r = sys.stdout.read()
    sys.stdout = normal_stdout
    return(r)


def patch_zlib(binary_data):
    def zlibsearch(data):
        r = []
        zlib_header = b'\x78\x9c'
        for offset in [zl.start() for zl in re.finditer(zlib_header, data)]:
            r.append(offset)
        return(r)

    '''Observed: Some individuals manipulate zlib and magic fields to break extract. This helps.'''
    r = ''
    pyz = re.finditer(b'\x50\x59\x5a\x00', binary_data)
    for line in pyz:
        x = line.start() + 17
    zlibcheck = binary_data[x:x + 2]
    file_data = re.sub(zlibcheck, b'\x78\x9c', binary_data)
    zlibs = zlibsearch(file_data)
    for offset in zlibs:
        f = file_data[offset:]
        try:
            test = zlib.decompress(f)
        except:
            continue
        if (b'import ') in test:
            if (b'\x01') in test:
                continue
            if (b'PyInst') in test or (b'pyi_') in test:
                continue
            r += test.decode()
    return(r)


def malicious_check(script_contents):
    '''Use this function to help determine if the script is malicious'''
    critical = re.findall(
        'ctypes|avlol|keylogger|backdoor|socket . socket|oo00oo',
        script_contents, re.I)  # spacing between period may indicate pyobfuscate
    high = re.findall('hide|hidden', script_contents, re.I)
    moderate = re.findall('socket.socket|base64.b64decode|subprocess', script_contents, re.I)
    score = (len(critical) * 3 + len(high) * 2 + len(moderate))
    if score >= 7:
        return('Malicious')
    if score >= 5:
        return('Likely Malicious')
    if score >= 3:
        return('Potentially Malicious')
    if score >= 2:
        return('Highly Suspicious')
    return('Likely Benign')


def screen_size():
    try:  # Get screen size (linux/osx/stdout redirect) to determine if we should page results.
        rows = subprocess.Popen(['stty', 'size'], stdout=subprocess.PIPE).communicate()[0].split()[0]
    except:  # If we're unable to get screen size (windows), set it ourselves:
        rows = 80
    return(rows)


if __name__ == '__main__':
    try:
        filename = sys.argv[1]
    except:
        print('Usage: %s [filename]' % __file__)
        sys.exit()

    try:
        fh = archive_viewer.get_archive(filename)
    except Exception as err:
        try:
            manual_warn = ('# Looks like the package has been manipulated. Manually carved - maybe incomplete.')
            manual_bin = open(filename, 'rb').read()
            data = patch_zlib(manual_bin)
            if data:
                rating = malicious_check(data)
                data = ('{}\n# Script: {} ({})\n'.format(
                    manual_warn, 'UNKNOWN_NAME', rating) +
                    '\n'.join(['\t' + indent for indent in data.split('\n')]))
            rows = screen_size()
            if len(data.split('\n')) > int(rows):
                pager(data)
                sys.exit()
            print(data)
            sys.exit()
        except:
            print('{}. Unable to carve anything manually.'.format(err))
        sys.exit()

    redirect_stdout()
    archive_viewer.show(filename, fh)
    d = redirect_stdout()
    rows = screen_size()
    scripts = [
        x for x in re.findall('\([0-9]+, [0-9]+, [0-9]+, [0-9]+, \'s\', u?\'([^\']+)\'\)', d)
        if 'pyi' not in x
    ]
    for script_name in scripts:
        x, data = fh.extract(script_name)
        data = data.decode('utf-8')
        rating = malicious_check(data)
        if data:
            data = '# Script: {} ({})\n'.format(script_name, rating) + '\n'.join(['\t' + indent for indent in data.split('\n')])
        if len(data.split('\n')) > int(rows):
            pager(data)
            sys.exit()
        print(data)
