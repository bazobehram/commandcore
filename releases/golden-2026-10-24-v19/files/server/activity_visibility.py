"""Bounded Activity projections. This is a display grammar, never a shell executor.

Unknown literals/code/output are withheld rather than regex-redacted. No raw
payloads are retained, including when a request fails validation.
"""
from __future__ import annotations

import posixpath
import re
import shlex
from typing import Any
from urllib.parse import urlsplit

_PATH_FIELDS = ('path', 'root', 'repo', 'source', 'destination', 'cwd')
_SENSITIVE = re.compile(
    r'secret|credential|password|passwd|token|bearer|auth|cookie|private|'
    r'api[_.-]?key|access[_.-]?key|session|\.env|\.ssh|\.aws|\.kube|'
    r'\.gnupg|id_rsa|id_ed25519|-----BEGIN|AKIA[A-Z0-9]{16}|eyJ', re.I)
# Reject encoded payloads, substitutions, environment assignments and raw code.
_FORBIDDEN = re.compile(r'[=$`\\%<>\x00-\x1f\x7f]')
_EXEC = {'pwd', 'uname', 'ls', 'mkdir', 'stat', 'df', 'du', 'git',
         'python', 'python3', 'pytest', 'npm', 'cargo', 'cd', 'pip', 'pip3'}
_GIT = {'status', 'diff', 'log', 'branch', 'rev-parse'}


def safe_path(value: Any) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 240:
        return None
    if _SENSITIVE.search(value):
        return '[restricted path]'
    if not re.fullmatch(r'[A-Za-z0-9_./ +@-]+', value):
        return None
    if '..' in value.split('/'):
        return None
    # Do not treat long opaque values as useful path hints.
    if any(len(p) > 48 for p in value.split('/')):
        return None
    return posixpath.normpath(value)


def _target(word: str) -> bool:
    return (bool(re.fullmatch(r'[A-Za-z0-9_./ @+-]{1,120}', word))
            and not word.startswith('-') and safe_path(word) not in (None, '[restricted path]'))


def _approved(words: list[str]) -> bool:
    """Finite developer command grammar; no free-form flags, code or messages."""
    name, *args = words
    if name not in _EXEC:  # Absolute executable paths are not verified programs.
        return False
    if name == 'pwd':
        return not args
    if name == 'uname':
        return all(a in {'-a', '-s', '-r', '-m'} for a in args)
    if name in {'cd', 'mkdir', 'ls', 'stat', 'df', 'du'}:
        flags = {'cd': set(), 'mkdir': {'-p'}, 'ls': {'-l', '-a', '-la', '-al', '-h'},
                 'stat': set(), 'df': {'-h'}, 'du': {'-h', '-s', '-sh'}}[name]
        return all(a in flags or _target(a) for a in args) and (name != 'cd' or len(args) == 1)
    if name == 'git':
        if not args or args[0] not in _GIT:
            return False
        # Deliberately exclude arbitrary refs, pathspecs and git -c settings.
        flags = {'status': {'--short', '--porcelain', '-sb'},
                 'diff': {'--stat', '--name-only', '--check', '--cached', '--staged'},
                 'log': {'--oneline', '-1', '-5', '-10'},
                 'branch': {'--show-current'}, 'rev-parse': {'--show-toplevel', '--is-inside-work-tree'}}
        return all(a in flags[args[0]] for a in args[1:])
    if name in {'python', 'python3'}:
        if args == ['--version']:
            return True
        if args[:2] == ['-m', 'pytest']:
            return _approved(['pytest', *args[2:]])
        if args[:2] == ['-m', 'pip']:
            return _approved(['pip', *args[2:]])
        return False
    if name in {'pip', 'pip3'}:
        # Known package only: never render arbitrary package/index URLs.
        return args in [['--version'], ['list'], ['install', 'oci-cli']]
    if name == 'pytest':
        return all(a in {'-q', '-v', '-x', '--collect-only'} or
                   (_target(a) and (a.endswith('.py') or a in {'tests', 'tests/'})) for a in args)
    if name == 'npm':
        return args in [['test'], ['ci'], ['run', 'build'], ['run', 'lint']]
    if name == 'cargo':
        return args in [['test'], ['build'], ['check'], ['fmt', '--check']]
    return False


def command_projection(value: Any) -> dict[str, Any]:
    withheld = {'command_visibility': 'withheld',
                'redaction_reason': 'Command arguments withheld: credentials, code or unsupported syntax may be present.'}
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        return withheld
    # Whole-payload check first: never reveal the safe prefix of a risky script.
    if _SENSITIVE.search(value) or _FORBIDDEN.search(value):
        return withheld
    # Preserve whether punctuation was quoted. shlex alone loses this and can
    # mislabel a literal '&&' argument as an actual shell step boundary.
    pattern = re.compile(r"(?P<space> +)|(?P<operator>&&|\|\||[;|])|(?P<word>'[^']*'|\"[^\"]*\"|[^ ;&|'\"]+)")
    tokens = []
    end = 0
    previous_word = False
    for match in pattern.finditer(value):
        if match.start() != end:
            return withheld
        end = match.end()
        if match.lastgroup == 'space':
            previous_word = False
            continue
        if match.lastgroup == 'word':
            if previous_word:  # Adjacent quoted/unquoted fragments are unsupported.
                return withheld
            try:
                decoded = shlex.split(match.group())
            except ValueError:
                return withheld
            if len(decoded) != 1:
                return withheld
            tokens.append(('word', decoded[0]))
            previous_word = True
        else:
            tokens.append(('operator', match.group()))
            previous_word = False
    if end != len(value) or not tokens or len(tokens) > 96:
        return withheld
    steps: list[list[str]] = [[]]
    operators = []
    for kind, token in tokens:
        if kind == 'operator':
            if not steps[-1]:
                return withheld
            operators.append(token)
            steps.append([])
        elif any(c in token for c in ';&|'):
            return withheld
        else:
            steps[-1].append(token)
    if not steps[-1] or len(steps) > 12:
        return withheld
    if all(_approved(step) for step in steps):
        displays = [shlex.join(step) for step in steps]
        display = displays[0]
        for op, step in zip(operators, displays[1:]):
            display += ' ' + op + ' ' + step
        return {'command_display': display, 'command_steps': displays,
                'command_visibility': 'validated', 'step_operators': operators}
    # Structure is useful even when argv is not safe. Only fixed known names
    # survive; no arbitrary executable, literal, option or script fragment.
    structure = [step[0] if step[0] in _EXEC else 'unrecognized command' for step in steps]
    return {**withheld, 'command_visibility': 'structure',
            'command_steps': [name + ' (arguments withheld)' for name in structure],
            'step_operators': operators,
            'redaction_reason': 'Only command structure shown; unsupported arguments withheld.'}


def visible_command(value: Any) -> str | None:
    return command_projection(value).get('command_display')


def safe_command_name(value: Any) -> str | None:
    projection = command_projection(value)
    steps = projection.get('command_steps', [])
    if steps:
        name = steps[0].split(' ', 1)[0]
        return name if name in _EXEC else None
    return None


def visible_public_url(value: Any) -> str | None:
    """HTTPS origin only. Paths, queries and fragments can all carry secrets."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return None
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or '\\' in value:
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme != 'https' or not host or parsed.username is not None
                or parsed.password is not None or parsed.port is not None):
            return None
    except ValueError:
        return None
    if not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', host) or _SENSITIVE.search(host):
        return None
    if any(len(label) > 48 for label in host.split('.')):
        return None
    return 'https://' + host + '/'


def safe_operation_detail(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {'operation': tool[:64]}
    for key in _PATH_FIELDS:
        path = safe_path(arguments.get(key))
        if path is not None:
            result[key] = path
    if tool in {'shell.exec', 'process.start'}:
        result.update(command_projection(arguments.get('command')))
        result['command_name'] = safe_command_name(arguments.get('command')) or 'Shell operation'
    elif tool.startswith('browser.'):
        public_url = visible_public_url(arguments.get('url'))
        if public_url:
            result['public_url'] = public_url
        result['url_visibility'] = 'HTTPS origin only; path, query, fragment and typed values withheld.'
    elif tool == 'git.run':
        argv = arguments.get('args')
        if isinstance(argv, list) and argv and isinstance(argv[0], str):
            result['git_subcommand'] = argv[0] if argv[0] in _GIT else 'Git arguments withheld'
    if tool in {'fs.write', 'fs.patch', 'fs.delete', 'fs.move', 'fs.copy', 'transfer.upload'}:
        result['effect'] = 'write'
    elif tool.startswith(('fs.read', 'fs.list', 'fs.stat', 'fs.search', 'git.diff', 'git.status')):
        result['effect'] = 'read'
    if tool == 'fs.patch' and isinstance(arguments.get('patches'), list):
        result['patch_count'] = min(len(arguments['patches']), 10000)
    if tool in {'fs.write', 'fs.patch', 'git.diff'}:
        result['preview'] = 'Diff/content unavailable: this feed retains no file contents or patch text.'
    result['output_policy'] = 'Raw output is not captured by this Activity feed.'
    return result
