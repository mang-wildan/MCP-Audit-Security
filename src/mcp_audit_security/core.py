"""Bounded, descriptor-relative Linux collectors. Never return file contents."""
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import subprocess
import time

MAX_FILE = 2 * 1024 * 1024
MAX_BYTES = 16 * 1024 * 1024
MAX_FILES = 1000
MAX_RESULTS = 500
MAX_SECONDS = 10
MAX_LOG_BYTES = 1024 * 1024
MAX_LINE = 8192
MAX_TRIAGE_ITEMS = 1000
RULES = {
    'PHP_TAG': re.compile(rb'<\?(?:php|=)', re.I),
    'PHP_DYNAMIC_EXEC': re.compile(rb'\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(', re.I),
    'PHP_OBFUSCATION': re.compile(rb'\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(', re.I),
    'PHP_REQUEST_INPUT': re.compile(rb'\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b', re.I),
}
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
PASSWD = '/etc/passwd'
PERSISTENCE = (
    ('cron_spool', '/var/spool/cron'),
    ('cron_d', '/etc/cron.d'),
    ('cron_daily', '/etc/cron.daily'),
    ('cron_weekly', '/etc/cron.weekly'),
    ('cron_monthly', '/etc/cron.monthly'),
    ('crontab', '/etc/crontab'),
    ('rc_local', '/etc/rc.local'),
    ('systemd_system', '/etc/systemd/system'),
    ('ld_preload', '/etc/ld.so.preload'),
    ('root_authorized_keys', '/root/.ssh/authorized_keys'),
    ('sshd_config_d', '/etc/ssh/sshd_config.d'),
)
COMMANDS = {('ss', '-H', '-lnt')}



class ConfigError(ValueError):
    pass


def parts(path, absolute=False):
    if not isinstance(path, str) or not path or '\x00' in path:
        raise ValueError('invalid path')
    p = PurePosixPath(path)
    if p.is_absolute() != absolute or any(x in ('.', '..', '') for x in path.split('/')[int(absolute):]):
        raise ValueError('invalid path')
    if len(path) > 4096:
        raise ValueError('invalid path')
    return p.parts[1:] if absolute else p.parts


def open_abs(path):
    segments = parts(path, True)
    fd = os.open('/', FLAGS | os.O_DIRECTORY)
    try:
        for i, name in enumerate(segments):
            new = os.open(name, FLAGS | (os.O_DIRECTORY if i < len(segments) - 1 else 0), dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_fd(fd, limit, budget=None):
    deadline = time.monotonic() + MAX_SECONDS
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise ValueError('not regular file')
    data = bytearray()
    while len(data) <= limit:
        if time.monotonic() >= deadline or (budget and not budget.active()):
            raise ValueError('time limit')
        chunk = os.read(fd, min(65536, limit + 1 - len(data)))
        if budget:
            budget.bytes += len(chunk)
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    raise ValueError('byte limit')


def read_abs(path, limit):
    fd = open_abs(path)
    try:
        return read_fd(fd, limit)
    finally:
        os.close(fd)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def triage_config(t):
    if not isinstance(t, dict) or not {'model', 'api_key_file'} <= set(t) or set(t) - {
            'model', 'api_key_file', 'max_items', 'max_file_bytes', 'timeout_seconds'}:
        raise ValueError('triage schema')
    if not isinstance(t['model'], str) or not re.fullmatch(r'[a-z0-9~][a-z0-9.\-/:]{0,99}', t['model']):
        raise ValueError('triage model')
    parts(t['api_key_file'], True)
    def bounded(key, default, low, high, clamp_low=False):
        value = t.get(key, default)
        if type(value) is not int or (not clamp_low and value < low):
            raise ValueError('triage ' + key)  # rejects bool, float, str; low invalid for strict keys
        if clamp_low and value < low:
            value = low
        return min(value, high)
    return {'model': t['model'], 'api_key_file': t['api_key_file'],
            'max_items': bounded('max_items', 50, 1, MAX_TRIAGE_ITEMS),
            'max_file_bytes': bounded('max_file_bytes', 262144, 1, MAX_FILE),
            'timeout_seconds': bounded('timeout_seconds', 30, 1, 120, clamp_low=True)}


def load_config(path):
    try:
        if not path:
            raise ValueError('explicit configuration required')
        config = strict_json(read_abs(path, 65536))
        if not isinstance(config, dict) or 'sites' not in config or set(config) - {'sites', 'triage'}:
            raise ValueError('schema')
        if 'triage' in config:
            config['triage'] = triage_config(config['triage'])
        sites = config['sites']
        if not isinstance(sites, dict) or not 1 <= len(sites) <= 32:
            raise ValueError('sites')
        for name, site in sites.items():
            if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', name) or not isinstance(site, dict):
                raise ValueError('site')
            if not {'webroot'} <= set(site) or set(site) - {'webroot', 'files_dir', 'manifest', 'logs'}:
                raise ValueError('site schema')
            for key in ('webroot', 'files_dir', 'manifest'):
                if key in site:
                    parts(site[key], True)
                    if site[key] == '/':
                        raise ValueError('root forbidden')
            logs = site.get('logs', {})
            if not isinstance(logs, dict) or len(logs) > 8:
                raise ValueError('logs')
            for key, value in logs.items():
                if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', key):
                    raise ValueError('log id')
                parts(value, True)
        return config
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise ConfigError('configuration invalid or inaccessible') from None


class Budget:
    def __init__(self):
        self.start = time.monotonic()
        self.files = 0
        self.bytes = 0
        self.result = {'items': [], 'errors': [], 'truncated': False}

    def active(self):
        ok = (time.monotonic() - self.start < MAX_SECONDS and self.files < MAX_FILES
              and self.bytes < MAX_BYTES and len(self.result['items']) < MAX_RESULTS)
        if not ok:
            self.result['truncated'] = True
        return ok

    def error(self, code):
        if len(self.result['errors']) < 32:
            self.result['errors'].append(code)
        else:
            self.result['truncated'] = True


def walk(fd, budget, prefix='', depth=0):
    if depth > 32:
        budget.error('depth_limit')
        budget.result['truncated'] = True
        return
    with os.scandir(fd) as entries:
        for entry in entries:
            if not budget.active():
                return
            budget.files += 1
            name = prefix + entry.name
            try:
                child = os.open(entry.name, FLAGS, dir_fd=fd)
                try:
                    st = os.fstat(child)
                    if stat.S_ISDIR(st.st_mode):
                        yield from walk(child, budget, name + '/', depth + 1)
                    elif stat.S_ISREG(st.st_mode):
                        yield name, child, st
                    else:
                        budget.error('special_file_skipped')
                finally:
                    os.close(child)
            except OSError:
                budget.error('entry_inaccessible_or_symlink')


def safe_label(value):
    # File names are untrusted too; bounded printable labels, never file content.
    return ''.join(c if c.isprintable() else '?' for c in value)[:240]


class Audit:
    def __init__(self, config):
        self.config = config

    def site(self, name):
        if name not in self.config['sites']:
            raise ValueError('unknown site')
        return self.config['sites'][name]

    def collect(self, roots, visitor):
        b = Budget()
        for label, path in roots:
            if not b.active():
                break
            try:
                fd = open_abs(path)
                try:
                    root_stat = os.fstat(fd)
                    if stat.S_ISREG(root_stat.st_mode):
                        entries = iter([('', fd, root_stat)])
                    elif stat.S_ISDIR(root_stat.st_mode):
                        entries = walk(fd, b)
                    else:
                        raise ValueError('not regular or directory')
                    for name, child, st in entries:
                        if not b.active():
                            break
                        if st.st_size > MAX_FILE or b.bytes + st.st_size > MAX_BYTES:
                            b.error('file_byte_limit')
                            b.result['truncated'] = True
                            continue
                        try:
                            data = read_fd(child, min(MAX_FILE, MAX_BYTES - b.bytes - 1), b)

                            visitor(b, label + '/' + name, st, data)
                        except (OSError, ValueError):
                            b.error('file_read_failed_or_limit')
                            b.result['truncated'] = True
                finally:
                    os.close(fd)
            except (OSError, ValueError):
                b.error('root_inaccessible_or_unsafe')
        return {**b.result, 'entries_examined': b.files, 'bytes_read': b.bytes}

    def web_integrity(self, site_id):
        """Inventory SHA-256 file website dari allowlist config, opsional banding baseline manifest."""
        site = self.site(site_id)
        baseline = None
        if 'manifest' in site:
            try:
                baseline = strict_json(read_abs(site['manifest'], MAX_FILE))
                if not isinstance(baseline, dict) or len(baseline) > MAX_FILES:
                    raise ValueError('manifest')
                for key, value in baseline.items():
                    parts(key)
                    if not key.startswith(('webroot/', 'files_dir/')) or not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
                        raise ValueError('manifest')
            except (OSError, ValueError, TypeError, RecursionError):
                return {'items': [], 'errors': ['invalid_or_inaccessible_manifest'], 'truncated': False}
        seen = set()
        def visit(b, name, st, data):
            digest = hashlib.sha256(data).hexdigest()
            # Compare using full path, not truncated presentation label.
            seen.add(name)
            item = {'path': safe_label(name), 'size': st.st_size, 'sha256': digest}
            if baseline is not None:
                item['baseline'] = 'new' if name not in baseline else ('match' if baseline[name] == digest else 'changed')
            b.result['items'].append(item)
        result = self.collect([(key, site[key]) for key in ('webroot', 'files_dir') if key in site], visit)
        if baseline is not None:
            result['missing'] = sorted(set(baseline) - seen)[:MAX_RESULTS] if not result['truncated'] and not result['errors'] else []
            result['baseline_complete'] = not result['truncated'] and not result['errors']
        return result

    def payload_scan(self, site_id):
        site = self.site(site_id)
        def visit(b, name, st, data):
            digest = hashlib.sha256(data).hexdigest()
            for rule, pattern in RULES.items():
                for match in pattern.finditer(data):
                    if not b.active():
                        return
                    b.result['items'].append({'path': safe_label(name), 'rule_id': rule,
                                              'line': data.count(b'\n', 0, match.start()) + 1,
                                              'sha256': digest})
        return self.collect([(k, site[k]) for k in ('webroot', 'files_dir') if k in site], visit)

    def log_timeline(self, site_id, log_id):
        logs = self.site(site_id).get('logs', {})
        if log_id not in logs:
            raise ValueError('unknown log')
        b = Budget()
        try:
            fd = open_abs(logs[log_id])
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError('not regular')
                offset = max(0, st.st_size - MAX_LOG_BYTES)
                os.lseek(fd, offset, os.SEEK_SET)
                data = os.read(fd, MAX_LOG_BYTES)
                b.bytes = len(data)
                b.result['truncated'] = offset > 0
            finally:
                os.close(fd)
            if offset:
                data = data.partition(b'\n')[2]
            # Common/combined access format only. Request target, IP, UA, referrer
            # and identity deliberately never leave collector.
            pattern = re.compile(rb'^\S+ \S+ \S+ \[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) [^"\r\n]*" ([1-5]\d{2}) (\d+|-)')
            for line in data.splitlines():
                if not b.active():
                    break
                if len(line) > MAX_LINE:
                    b.error('line_too_long')
                    continue
                match = pattern.match(line)
                if match:
                    stamp, method, status, size = match.groups()
                    b.result['items'].append({'timestamp': stamp.decode('ascii'), 'method': method.decode(),
                                              'status': int(status), 'response_bytes': None if size == b'-' else int(size)})
                else:
                    b.error('unparsed_line')
        except (OSError, ValueError):
            b.error('log_inaccessible_or_unsafe')
        return {**b.result, 'bytes_read': b.bytes}

    def persistence_audit(self):
        def visit(b, name, st, data):
            b.result['items'].append({'path': safe_label(name), 'sha256': hashlib.sha256(data).hexdigest(),
                                      'size': st.st_size, 'mode': oct(stat.S_IMODE(st.st_mode)),
                                      'uid': st.st_uid, 'gid': st.st_gid, 'mtime_ns': st.st_mtime_ns})
        result = self.collect(PERSISTENCE, visit)
        accounts = []
        try:
            lines = read_abs(PASSWD, MAX_FILE).splitlines()
            if len(lines) > MAX_RESULTS:
                result['truncated'] = True
            for line in lines[:MAX_RESULTS]:
                fields = line.split(b':')
                if len(fields) == 7 and fields[2].isdigit() and fields[3].isdigit():
                    # Names/home/shell can contain attacker text. Only IDs and classifications.
                    accounts.append({'uid': int(fields[2]), 'gid': int(fields[3]),
                                     'interactive_shell': fields[6] not in (b'/bin/false', b'/sbin/nologin', b'/usr/sbin/nologin')})
        except (OSError, ValueError):
            result['errors'].append('accounts_inaccessible')
        result['accounts'] = accounts
        return result

    def host_inventory(self):
        # No process args, environment, addresses or arbitrary command output.
        kernel = os.uname()
        result = {'kernel': {'system': kernel.sysname, 'release': kernel.release,
                              'machine': kernel.machine}, 'euid': os.geteuid(), 'errors': [],
                  'truncated': False, 'listening_tcp_ports': []}
        try:
            distro = {}
            for line in read_abs('/etc/os-release', 8192).decode('utf-8', 'replace').splitlines():
                key, _, value = line.partition('=')
                if key in ('NAME', 'PRETTY_NAME', 'ID', 'VERSION_ID', 'VERSION_CODENAME'):
                    distro[key] = value.strip('"\'' )[:120]
            result['distro'] = distro
        except (OSError, ValueError):
            result['errors'].append('os_release_unavailable')
        try:
            output, truncated = fixed_command(('ss', '-H', '-lnt'))
            result['truncated'] = truncated
            ports = set()
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 4:
                    port = fields[3].rsplit(b':', 1)[-1]
                    if port.isdigit() and 0 <= int(port) <= 65535:
                        ports.add(int(port))
            result['listening_tcp_ports'] = sorted(ports)[:MAX_RESULTS]
            result['truncated'] |= len(ports) > MAX_RESULTS
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            result['errors'].append('socket_inventory_unavailable')
        return result


def fixed_command(args):
    """Fixed argv, trusted executable path, bounded pipe and child lifetime."""
    import selectors
    if args not in COMMANDS:
        raise ValueError('command not allowed')
    executable = next((p for p in ('/usr/bin/' + args[0], '/usr/sbin/' + args[0], '/bin/' + args[0]) if os.path.isfile(p)), None)
    if executable is None:
        raise OSError('command missing')
    with subprocess.Popen([executable, *args[1:]], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, close_fds=True) as proc:
        output = bytearray()
        deadline = time.monotonic() + 2
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while len(output) < 65536:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError('command timeout')
                    chunk = os.read(proc.stdout.fileno(), min(8192, 65536 - len(output)))
                    if not chunk:
                        if proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                            raise OSError('command failed')
                        return bytes(output), False
                    output.extend(chunk)
                return bytes(output), True
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=2)
