"""Configuration: the repository's shared config and the user's private terms.

Two files, two audiences:

``.secret-scan.json``
    Committed. Allow-list entries, ignored paths, disabled and extra rules.
    Every exception carries a ``reason``. An exception nobody can justify
    shouldn't exist.

Private terms
    Never committed. Names, addresses and other personal or client details to
    flag. Read from, in order:

    - ``$XDG_CONFIG_HOME/secret-scan/private.json`` (default ``~/.config/...``),
      which applies to every repository you scan;
    - ``.secret-scan.local.json`` at the scan root, which is git-ignored;
    - the ``SECRET_SCAN_PRIVATE_TERMS`` environment variable (one term per
      line), meant for a CI secret.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secret_scan.errors import SecretScanError
from secret_scan.globs import compile_glob
from secret_scan.rules import CONTENT_RULES, PATH_RULES, PathRule, Rule, builtin_rule_ids

CONFIG_FILE = ".secret-scan.json"
LOCAL_FILE = ".secret-scan.local.json"
PRIVATE_ENV = "SECRET_SCAN_PRIVATE_TERMS"
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
PRIVATE_TERM_RULE_ID = "private-term"
_RULE_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,63}\Z")
_MIN_TERM_LENGTH = 3


@dataclass(frozen=True)
class AllowEntry:
    reason: str
    rule: str | None = None
    path: re.Pattern[str] | None = None
    value: str | None = None

    def matches(self, rule_id: str, path: str, value: str | None) -> bool:
        if self.rule is not None and self.rule != rule_id:
            return False
        if self.path is not None and not self.path.match(path):
            return False
        return self.value is None or self.value == value


@dataclass
class Settings:
    content_rules: list[Rule]
    path_rules: list[PathRule]
    allow: list[AllowEntry] = field(default_factory=list)
    ignore: list[re.Pattern[str]] = field(default_factory=list)
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    #: Where private terms came from, for display. Never the terms themselves.
    private_sources: list[str] = field(default_factory=list)

    @property
    def all_rules(self) -> list[Rule | PathRule]:
        return [*self.content_rules, *self.path_rules]

    def rule_why(self, rule_id: str) -> str:
        for r in self.all_rules:
            if r.id == rule_id:
                return r.why
        return ""

    def is_ignored(self, path: str) -> bool:
        return any(g.match(path) for g in self.ignore)


def user_private_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "secret-scan" / "private.json"


# --- loading ---------------------------------------------------------------


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise SecretScanError(f"{path}: can't read: {e.strerror}") from None
    except json.JSONDecodeError as e:
        raise SecretScanError(f"{path}: invalid JSON at line {e.lineno}: {e.msg}") from None
    if not isinstance(data, dict):
        raise SecretScanError(f"{path}: expected a JSON object at the top level")
    return data


def _check_keys(where: str, obj: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise SecretScanError(
            f"{where}: unknown key(s) {', '.join(unknown)}; allowed: {', '.join(sorted(allowed))}"
        )


def _opt(where: str, obj: Mapping[str, Any], key: str) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SecretScanError(f"{where}: '{key}' must be a non-empty string")
    return value


def _req(where: str, obj: Mapping[str, Any], key: str) -> str:
    value = _opt(where, obj, key)
    if value is None:
        raise SecretScanError(f"{where}: '{key}' is required")
    return value


def _list(where: str, obj: Mapping[str, Any], key: str) -> list[Any]:
    value = obj.get(key, [])
    if not isinstance(value, list):
        raise SecretScanError(f"{where}: '{key}' must be a list")
    return value


def _obj(where: str, item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise SecretScanError(f"{where}: expected an object")
    return item


def _glob(where: str, pattern: str) -> re.Pattern[str]:
    try:
        return compile_glob(pattern)
    except (ValueError, re.error) as e:
        raise SecretScanError(f"{where}: invalid path glob: {e}") from None


def _custom_rule(where: str, item: dict[str, Any], origin: str) -> Rule:
    _check_keys(where, item, {"id", "why", "pattern", "ignoreCase"})
    rule_id = _req(where, item, "id")
    why = _req(where, item, "why")
    pattern = _req(where, item, "pattern")
    if not _RULE_ID.match(rule_id):
        raise SecretScanError(
            f"{where}: rule id must be lowercase letters, digits and hyphens (2-64 chars)"
        )
    ignore_case = item.get("ignoreCase", False)
    if not isinstance(ignore_case, bool):
        raise SecretScanError(f"{where}: 'ignoreCase' must be true or false")
    try:
        compiled = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as e:
        raise SecretScanError(f"{where}: invalid pattern: {e}") from None
    return Rule(rule_id, why, compiled, check_placeholder=False, origin=origin)


@dataclass
class _Private:
    terms: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


def _load_private_file(path: Path, into: _Private) -> None:
    data = _read_json(path)
    where = str(path)
    _check_keys(where, data, {"terms", "patterns"})
    for i, term in enumerate(_list(where, data, "terms")):
        if not isinstance(term, str) or len(term.strip()) < _MIN_TERM_LENGTH:
            raise SecretScanError(
                f"{where}: terms[{i}] must be a string of at least {_MIN_TERM_LENGTH} characters"
            )
        into.terms.append(term.strip())
    for i, item in enumerate(_list(where, data, "patterns")):
        w = f"{where}: patterns[{i}]"
        into.rules.append(_custom_rule(w, _obj(w, item), "private"))
    into.sources.append(where)


def _private_term_rule(terms: list[str]) -> Rule:
    unique = sorted({t.casefold(): t for t in terms}.values(), key=len, reverse=True)
    alternation = "|".join(re.escape(t) for t in unique)
    return Rule(
        PRIVATE_TERM_RULE_ID,
        "Matches an entry in your private terms list.",
        re.compile(rf"(?<![A-Za-z0-9])(?:{alternation})(?![A-Za-z0-9])", re.IGNORECASE),
        check_placeholder=False,
        origin="private",
    )


def load_settings(
    root: Path,
    *,
    config_path: Path | None = None,
    local_path: Path | None = None,
    use_user_file: bool = True,
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Build the effective rule set and exceptions for a scan rooted at ``root``.

    ``config_path`` and ``local_path`` override the default locations. An
    explicitly given file must exist; a default one is optional.
    """
    env = os.environ if environ is None else environ

    # Private terms first: their rule ids take part in clash checks below.
    private = _Private()
    candidates: list[tuple[Path, bool]] = []
    if use_user_file:
        candidates.append((user_private_file(), False))
    candidates.append((local_path or root / LOCAL_FILE, local_path is not None))
    for path, required in candidates:
        if path.is_file():
            _load_private_file(path, private)
        elif required:
            raise SecretScanError(f"{path}: private terms file not found")
    env_terms = [t.strip() for t in env.get(PRIVATE_ENV, "").splitlines() if t.strip()]
    short = [t for t in env_terms if len(t) < _MIN_TERM_LENGTH]
    if short:
        raise SecretScanError(
            f"{PRIVATE_ENV}: every term must be at least {_MIN_TERM_LENGTH} characters"
        )
    if env_terms:
        private.terms.extend(env_terms)
        private.sources.append(f"${PRIVATE_ENV}")

    content_rules = list(CONTENT_RULES)
    path_rules = list(PATH_RULES)
    settings = Settings(content_rules, path_rules, private_sources=private.sources)

    known = builtin_rule_ids() | {PRIVATE_TERM_RULE_ID}
    for r in private.rules:
        if r.id in known:
            raise SecretScanError(f"private pattern '{r.id}' clashes with an existing rule id")
        known.add(r.id)

    # Before the repo config, so its 'disable' entries can turn these off too.
    if private.terms:
        settings.content_rules.append(_private_term_rule(private.terms))
    settings.content_rules.extend(private.rules)

    cfg_file = config_path or root / CONFIG_FILE
    if cfg_file.is_file():
        _apply_repo_config(cfg_file, settings, known)
    elif config_path is not None:
        raise SecretScanError(f"{config_path}: config file not found")
    return settings


def _apply_repo_config(path: Path, settings: Settings, known: set[str]) -> None:
    data = _read_json(path)
    name = path.name
    _check_keys(name, data, {"$schema", "ignore", "allow", "disable", "rules", "maxFileBytes"})

    for i, item in enumerate(_list(name, data, "rules")):
        where = f"{name}: rules[{i}]"
        rule = _custom_rule(where, _obj(where, item), "config")
        if rule.id in known:
            raise SecretScanError(f"{where}: id '{rule.id}' is already in use")
        known.add(rule.id)
        settings.content_rules.append(rule)

    disabled: set[str] = set()
    for i, item in enumerate(_list(name, data, "disable")):
        where = f"{name}: disable[{i}]"
        obj = _obj(where, item)
        _check_keys(where, obj, {"rule", "reason"})
        rule_id = _req(where, obj, "rule")
        _req(where, obj, "reason")
        if rule_id not in known:
            raise SecretScanError(f"{where}: unknown rule '{rule_id}' (see --list-rules)")
        disabled.add(rule_id)
    settings.content_rules = [r for r in settings.content_rules if r.id not in disabled]
    settings.path_rules = [r for r in settings.path_rules if r.id not in disabled]

    for i, item in enumerate(_list(name, data, "ignore")):
        where = f"{name}: ignore[{i}]"
        obj = _obj(where, item)
        _check_keys(where, obj, {"path", "reason"})
        pattern = _req(where, obj, "path")
        _req(where, obj, "reason")
        settings.ignore.append(_glob(where, pattern))

    for i, item in enumerate(_list(name, data, "allow")):
        where = f"{name}: allow[{i}]"
        obj = _obj(where, item)
        _check_keys(where, obj, {"rule", "path", "value", "reason"})
        reason = _req(where, obj, "reason")
        allow_rule = _opt(where, obj, "rule")
        path_glob = _opt(where, obj, "path")
        # Values are compared exactly, so don't strip or validate their content.
        value = obj.get("value")
        if value is not None and (not isinstance(value, str) or not value):
            raise SecretScanError(f"{where}: 'value' must be a non-empty string")
        if value is None and path_glob is None:
            raise SecretScanError(
                f"{where}: give a 'value', or a 'path' (with an optional 'rule'). "
                "To turn a rule off everywhere, use 'disable'"
            )
        if value is None and allow_rule is None:
            raise SecretScanError(
                f"{where}: an allow entry with only a 'path' skips nothing specific. "
                "Add a 'rule', or use 'ignore' to skip the path entirely"
            )
        if allow_rule is not None and allow_rule not in known:
            raise SecretScanError(f"{where}: unknown rule '{allow_rule}' (see --list-rules)")
        settings.allow.append(
            AllowEntry(
                reason=reason,
                rule=allow_rule,
                path=_glob(where, path_glob) if path_glob else None,
                value=value,
            )
        )

    max_bytes = data.get("maxFileBytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise SecretScanError(f"{name}: 'maxFileBytes' must be a positive integer")
    settings.max_file_bytes = max_bytes
