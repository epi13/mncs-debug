"""Doctor-facing remediation for debugger-owned infrastructure.

This provider speaks `mncs.remediation/1` over the repository domain for the
mncs-debug checkout. It repairs only debugger infrastructure that is
mechanically regenerable:

- descriptor library entries pointing at missing directories (dropped);
- descriptors missing the extracted-stdlib entry their module needs (added);
- stale frozen interface identities and host bindings (re-frozen only when
  the MNCS module source is unchanged versus git, so a local semantic edit
  is never silently blessed).

It never alters a debugged program, never invents evidence, and never
mutates outside `--changed-path` hints. Detection is read-only; every
mutation carries before/after fingerprints and a validation verdict.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .runner import resolve_mncs

REMEDIATION_SCHEMA = "mncs.remediation/1"
PROVIDER_ID = "mncs-debug"

_GENERATOR_RELATIVE = Path("scripts/generate_host_bindings.py")

# Descriptors invoked bare (`run-app DESCRIPTOR` with no caller library roots)
# must resolve their module imports from their own entries alone. All other
# descriptors are completed by their invoker's explicit roots.
_SELF_SUFFICIENT_DESCRIPTORS = frozenset({"native-applications/debug-diagnostic-coherence.json"})


@dataclass
class _Item:
    id: str
    check: str
    path: str  # scope-relative path of the file that would be mutated
    detail: str
    severity: str = "error"  # error | warning | info
    repair_class: str | None = None  # safe_automatic | bounded_reconciliation
    before: str | None = None
    after: str | None = None
    validated: bool = False
    action: str = ""  # escalation action when not repaired


@dataclass
class _Run:
    target: Path
    dry_run: bool
    hints: list[str]
    budget: int
    mncs_path: Path | None
    repairs: list[_Item] = field(default_factory=list)
    reconciliations: list[_Item] = field(default_factory=list)
    escalations: list[_Item] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    items_done: int = 0
    exhausted: bool = False
    errors_before: int = 0

    def hinted(self, path: str) -> bool:
        if not self.hints:
            return True
        return any(path == hint or path.startswith(hint.rstrip("/") + "/") for hint in self.hints)


def _fingerprint(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _run_git_clean(target: Path, relative: str) -> bool | None:
    """Return True when the file is unmodified versus git HEAD (None unknown)."""

    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(target), "status", "--porcelain", "--", relative],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="replace").strip() == ""


def _derived_stdlib(target: Path) -> Path | None:
    override = os.environ.get("MNCS_STDLIB_ROOT")
    if override is not None:
        if not override:
            return None
        candidate = Path(override)
        library = candidate if candidate.name == "library" else candidate / "library"
        return library if library.is_dir() else None
    candidate = target.parent / "mncs-stdlib" / "library"
    return candidate if candidate.is_dir() else None


def _resolve_mncs(explicit: str | None) -> Path | None:
    try:
        return resolve_mncs(explicit)
    except Exception:
        return None


def _observe_abi(mncs_path: Path, source: Path, libraries: list[Path]) -> tuple[str | None, str | None]:
    """Return (interface_identity, error_text) for one MNCS module."""

    environment = dict(os.environ)
    if libraries:
        environment["MNCS_LIBRARY_PATH"] = os.pathsep.join(os.fspath(path) for path in libraries)
    else:
        environment.pop("MNCS_LIBRARY_PATH", None)
    try:
        completed = subprocess.run(
            [os.fspath(mncs_path), "abi", os.fspath(source)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            timeout=180,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"could not start toolchain: {exc}"
    if completed.returncode != 0:
        detail = (completed.stderr.decode("utf-8", errors="replace").strip() or f"exit {completed.returncode}")
        return None, detail[:1024]
    try:
        document = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"toolchain returned invalid ABI JSON: {exc}"
    identity_value = document.get("interface_identity") if isinstance(document, dict) else None
    if not isinstance(identity_value, str) or not identity_value:
        return None, "toolchain ABI document has no interface_identity"
    return identity_value, None


def _read_json(path: Path) -> tuple[Any, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except OSError as exc:
        return None, f"unreadable: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"


def _write_json(path: Path, value: Any) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _check_descriptor(run: _Run, relative: str, abi_cache: dict[str, tuple[str | None, str | None]]) -> None:
    path = run.target / relative
    document, error = _read_json(path)
    if error is not None:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:unparseable-descriptor:{relative}",
                check="descriptor-libraries",
                path=relative,
                detail=f"{relative} is {error}",
                severity="error",
                action=f"repair the JSON syntax of {relative}, then re-run remediation",
            )
        )
        return
    if not isinstance(document, dict):
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:unparseable-descriptor:{relative}",
                check="descriptor-libraries",
                path=relative,
                detail=f"{relative} is not a JSON object",
                severity="error",
                action=f"repair the JSON structure of {relative}, then re-run remediation",
            )
        )
        return
    libraries = document.get("libraries")
    if not isinstance(libraries, list):
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:descriptor-libraries-shape:{relative}",
                check="descriptor-libraries",
                path=relative,
                detail=f"{relative} has no libraries array",
                severity="error",
                action=f"restore the libraries array of {relative}, then re-run remediation",
            )
        )
        return
    missing = [
        entry
        for entry in libraries
        if isinstance(entry, str) and not (path.parent / entry).is_dir()
    ]
    if missing and run.hinted(relative):
        item = _Item(
            id=f"{PROVIDER_ID}:dead-descriptor-library:{relative}",
            check="descriptor-libraries",
            path=relative,
            detail=f"{relative} drops {len(missing)} missing librar{'y' if len(missing) == 1 else 'ies'}: {', '.join(missing[:4])}",
            severity="error",
            repair_class="safe_automatic",
            before=_fingerprint(path),
        )
        run.repairs.append(item)
    elif missing:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:hint-scope-excluded:{relative}",
                check="descriptor-libraries",
                path=relative,
                detail=f"{relative} has {len(missing)} missing librar{'y' if len(missing) == 1 else 'ies'} outside changed-path hints",
                severity="info",
                action="re-run without hints or with covering hints to drop the dead entries",
            )
        )
    # Identity coherence needs the surviving (declared plus derived) roots.
    source_rel = document.get("source")
    frozen = document.get("interface_identity")
    if not isinstance(source_rel, str) or not isinstance(frozen, str):
        return
    if run.mncs_path is None:
        return  # toolchain-missing escalation is emitted once by the driver
    source = (path.parent / source_rel).resolve()
    if not source.is_file():
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:descriptor-source-missing:{relative}",
                check="descriptor-identity",
                path=relative,
                detail=f"{relative} source {source_rel} is missing",
                severity="error",
                action=f"restore the module source of {relative}, then re-run remediation",
            )
        )
        return
    bare_roots = [(path.parent / entry).resolve() for entry in libraries if isinstance(entry, str) and (path.parent / entry).is_dir()]
    stdlib = _derived_stdlib(run.target)
    self_sufficient = relative in _SELF_SUFFICIENT_DESCRIPTORS
    if self_sufficient:
        roots = list(bare_roots)
    else:
        roots = list(bare_roots)
        if stdlib is not None and stdlib.resolve() not in roots:
            roots.append(stdlib.resolve())
        workspace = run.target.parent
        for candidate in (
            workspace / "MNCS-Commons" / "src" / "mncs_commons" / "mesh" / "mncs",
            workspace / "mncs-test",
            workspace / "mncs-test" / "native",
        ):
            if candidate.is_dir() and candidate.resolve() not in roots:
                roots.append(candidate.resolve())
    cache_key = os.fspath(source) + "\0" + "\0".join(sorted(os.fspath(root) for root in roots))
    if cache_key not in abi_cache:
        abi_cache[cache_key] = _observe_abi(run.mncs_path, source, roots)
    observed, abi_error = abi_cache[cache_key]
    run.checks.append({"check": "descriptor-identity", "path": relative, "observed": observed, "error": abi_error})
    if observed is None and abi_error and "unavailable to the resolver" in abi_error and self_sufficient:
        declared = {(path.parent / item).resolve() for item in libraries if isinstance(item, str)}
        if stdlib is not None and stdlib.resolve() not in declared:
            if run.hinted(relative):
                try:
                    entry = os.path.relpath(stdlib.resolve(), path.parent.resolve())
                except (OSError, ValueError):
                    entry = None
                if entry is not None:
                    run.repairs.append(
                        _Item(
                            id=f"{PROVIDER_ID}:missing-stdlib-entry:{relative}",
                            check="descriptor-libraries",
                            path=relative,
                            detail=f"{relative} gains stdlib entry {entry} required by its bare invocation",
                            severity="error",
                            repair_class="safe_automatic",
                            before=_fingerprint(path),
                        )
                    )
                    return
            else:
                run.escalations.append(
                    _Item(
                        id=f"{PROVIDER_ID}:hint-scope-excluded:{relative}",
                        check="descriptor-libraries",
                        path=relative,
                        detail=f"{relative} missing stdlib entry is outside changed-path hints",
                        severity="info",
                        action="re-run without hints or with covering hints to add the stdlib entry",
                    )
                )
                return
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:resolver-unavailable:{relative}",
                check="descriptor-identity",
                path=relative,
                detail=f"{relative} module imports do not resolve: {abi_error[:256]}",
                severity="error",
                action="supply the missing library roots, then re-run remediation",
            )
        )
        return
    if observed is None:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:abi-failed:{relative}",
                check="descriptor-identity",
                path=relative,
                detail=f"{relative} toolchain ABI failed: {(abi_error or 'unknown error')[:256]}",
                severity="error",
                action=f"toolchain ABI failed ({(abi_error or 'unknown error')[:256]}); inspect it, then re-run remediation",
            )
        )
        return
    if observed == frozen:
        return
    try:
        source_scope_rel = str(source.resolve().relative_to(run.target.resolve()))
    except ValueError:
        source_scope_rel = None
    clean = _run_git_clean(run.target, source_scope_rel) if source_scope_rel else None
    if clean is True and run.hinted(relative):
        run.reconciliations.append(
            _Item(
                id=f"{PROVIDER_ID}:stale-descriptor-identity:{relative}",
                check="descriptor-identity",
                path=relative,
                detail=f"{relative} re-freezes {frozen[:12]} to {observed[:12]} (module source unchanged)",
                severity="error",
                repair_class="bounded_reconciliation",
                before=_fingerprint(path),
                action=observed,
            )
        )
    elif clean is True:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:hint-scope-excluded:{relative}",
                check="descriptor-identity",
                path=relative,
                detail=f"{relative} identity drift is outside changed-path hints",
                severity="info",
                action="re-run without hints or with covering hints to re-freeze the identity",
            )
        )
    else:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:semantic-change-review:{relative}",
                check="descriptor-identity",
                path=relative,
                detail=f"{relative} identity drift with unconfirmed module source (git: {'dirty' if clean is False else 'unknown'})",
                severity="error",
                action="review the module change, then re-freeze the descriptor identity deliberately",
            )
        )


_BINDING_IDENTITY_RE = re.compile(r"^INTERFACE_IDENTITY\s*=\s*'([0-9a-f]+)'\s*$", re.MULTILINE)


def _check_binding(run: _Run, abi_cache: dict[str, tuple[str | None, str | None]]) -> None:
    relative = "mncs_debug/generated/debug.py"
    path = run.target / relative
    if not path.is_file():
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:binding-missing:{relative}",
                check="binding-identity",
                path=relative,
                detail=f"{relative} is missing",
                severity="error",
                action=f"regenerate {relative} from the mncs.debug ABI, then re-run remediation",
            )
        )
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:binding-unreadable:{relative}",
                check="binding-identity",
                path=relative,
                detail=f"{relative} is unreadable: {exc}",
                severity="error",
                action=f"restore {relative}, then re-run remediation",
            )
        )
        return
    match = _BINDING_IDENTITY_RE.search(text)
    if match is None:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:binding-unparseable:{relative}",
                check="binding-identity",
                path=relative,
                detail=f"{relative} carries no parseable INTERFACE_IDENTITY",
                severity="error",
                action=f"regenerate {relative} from the mncs.debug ABI, then re-run remediation",
            )
        )
        return
    if run.mncs_path is None:
        return  # toolchain-missing escalation is emitted once by the driver
    frozen = match.group(1)
    source = run.target / "native/mncs/debug/debug.mncs"
    if not source.is_file():
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:binding-source-missing:{relative}",
                check="binding-identity",
                path=relative,
                detail="native/mncs/debug/debug.mncs is missing",
                severity="error",
                action="restore the native debug core, then re-run remediation",
            )
        )
        return
    roots: list[Path] = []
    configured = os.environ.get("MNCS_LIBRARY_PATH", "")
    roots.extend(Path(item) for item in configured.split(os.pathsep) if item)
    stdlib = _derived_stdlib(run.target)
    if stdlib is not None:
        roots.append(stdlib)
    workspace = run.target.parent
    for candidate in (
        workspace / "MNCS-Commons" / "src" / "mncs_commons" / "mesh" / "mncs",
        workspace / "mncs-test",
        workspace / "mncs-test" / "native",
    ):
        if candidate.is_dir():
            roots.append(candidate)
    roots = [path.resolve() for path in roots if path.is_dir()]
    cache_key = os.fspath(source.resolve()) + "\0" + "\0".join(sorted(os.fspath(root) for root in roots))
    if cache_key not in abi_cache:
        abi_cache[cache_key] = _observe_abi(run.mncs_path, source, roots)
    observed, abi_error = abi_cache[cache_key]
    run.checks.append({"check": "binding-identity", "path": relative, "observed": observed, "error": abi_error})
    if observed is None:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:binding-abi-failed:{relative}",
                check="binding-identity",
                path=relative,
                detail=f"mncs.debug ABI failed: {(abi_error or 'unknown error')[:256]}",
                severity="error",
                action=f"mncs.debug ABI failed ({(abi_error or 'unknown error')[:256]}); inspect it, then re-run remediation",
            )
        )
        return
    if observed == frozen:
        return
    clean = _run_git_clean(run.target, "native/mncs/debug/debug.mncs")
    if clean is True and run.hinted(relative):
        run.reconciliations.append(
            _Item(
                id=f"{PROVIDER_ID}:stale-binding:{relative}",
                check="binding-identity",
                path=relative,
                detail=f"{relative} regenerates {frozen[:12]} to {observed[:12]} (module source unchanged)",
                severity="error",
                repair_class="bounded_reconciliation",
                before=_fingerprint(path),
                action=observed,
            )
        )
    elif clean is True:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:hint-scope-excluded:{relative}",
                check="binding-identity",
                path=relative,
                detail=f"{relative} binding drift is outside changed-path hints",
                severity="info",
                action="re-run without hints or with covering hints to regenerate the binding",
            )
        )
    else:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:semantic-change-review:{relative}",
                check="binding-identity",
                path=relative,
                detail=f"{relative} binding drift with unconfirmed module source (git: {'dirty' if clean is False else 'unknown'})",
                severity="error",
                action="review the native core change, then regenerate the binding deliberately",
            )
        )


def _apply_dead_libraries(run: _Run, item: _Item) -> bool:
    path = run.target / item.path
    document, error = _read_json(path)
    if error is not None or not isinstance(document, dict) or not isinstance(document.get("libraries"), list):
        return False
    document["libraries"] = [
        entry for entry in document["libraries"]
        if not isinstance(entry, str) or (path.parent / entry).is_dir()
    ]
    _write_json(path, document)
    return all((path.parent / entry).is_dir() for entry in document["libraries"] if isinstance(entry, str))


def _apply_stdlib_entry(run: _Run, item: _Item) -> bool:
    path = run.target / item.path
    document, error = _read_json(path)
    if error is not None or not isinstance(document, dict) or not isinstance(document.get("libraries"), list):
        return False
    stdlib = _derived_stdlib(run.target)
    if stdlib is None:
        return False
    try:
        entry = os.path.relpath(stdlib.resolve(), path.parent.resolve())
    except (OSError, ValueError):
        return False
    declared = {(path.parent / existing).resolve() for existing in document["libraries"] if isinstance(existing, str)}
    if stdlib.resolve() in declared:
        return True
    document["libraries"] = [entry, *[existing for existing in document["libraries"]]]
    _write_json(path, document)
    # Validation is the toolchain observation itself: the module must admit.
    roots = [(path.parent / existing).resolve() for existing in document["libraries"] if isinstance(existing, str) and (path.parent / existing).is_dir()]
    source_rel = document.get("source")
    if not isinstance(source_rel, str) or run.mncs_path is None:
        return False
    source = (path.parent / source_rel).resolve()
    if not source.is_file():
        return False
    observed, _ = _observe_abi(run.mncs_path, source, roots)
    return observed is not None


def _apply_descriptor_identity(run: _Run, item: _Item) -> bool:
    path = run.target / item.path
    document, error = _read_json(path)
    if error is not None or not isinstance(document, dict):
        return False
    document["interface_identity"] = item.action
    _write_json(path, document)
    reread, reread_error = _read_json(path)
    return reread_error is None and isinstance(reread, dict) and reread.get("interface_identity") == item.action


def _apply_binding_regeneration(run: _Run, item: _Item) -> bool:
    generator = run.target.parent / "mncs-language" / _GENERATOR_RELATIVE
    if not generator.is_file():
        return False
    source = run.target / "native/mncs/debug/debug.mncs"
    if not source.is_file() or run.mncs_path is None:
        return False
    import tempfile

    with tempfile.TemporaryDirectory(prefix="mncs-debug-remediate-") as directory:
        abi_path = Path(directory) / "abi.json"
        environment = dict(os.environ)
        stdlib = _derived_stdlib(run.target)
        workspace = run.target.parent
        roots = [stdlib] if stdlib is not None else []
        for candidate in (
            workspace / "MNCS-Commons" / "src" / "mncs_commons" / "mesh" / "mncs",
            workspace / "mncs-test",
            workspace / "mncs-test" / "native",
        ):
            if candidate.is_dir():
                roots.append(candidate)
        environment["MNCS_LIBRARY_PATH"] = os.pathsep.join(os.fspath(path) for path in roots if path.is_dir())
        try:
            dumped = subprocess.run(
                [os.fspath(run.mncs_path), "abi", os.fspath(source)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=180,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if dumped.returncode != 0:
            return False
        abi_path.write_bytes(dumped.stdout)
        try:
            completed = subprocess.run(
                ["python3", os.fspath(generator), "--abi", os.fspath(abi_path),
                 "--language", "python", "--output", os.fspath(run.target / item.path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if completed.returncode != 0:
            return False
    try:
        text = (run.target / item.path).read_text(encoding="utf-8")
    except OSError:
        return False
    match = _BINDING_IDENTITY_RE.search(text)
    return match is not None and match.group(1) == item.action


def _apply_item(run: _Run, item: _Item) -> bool:
    if item.id.startswith(f"{PROVIDER_ID}:dead-descriptor-library:"):
        return _apply_dead_libraries(run, item)
    if item.id.startswith(f"{PROVIDER_ID}:missing-stdlib-entry:"):
        return _apply_stdlib_entry(run, item)
    if item.id.startswith(f"{PROVIDER_ID}:stale-descriptor-identity:"):
        return _apply_descriptor_identity(run, item)
    if item.id.startswith(f"{PROVIDER_ID}:stale-binding:"):
        return _apply_binding_regeneration(run, item)
    return False


def _validate_hints(hints: list[str]) -> str | None:
    for hint in hints:
        if not hint or hint.startswith("/") or ".." in Path(hint).parts:
            return hint
    return None


def remediate(
    *,
    target: Path,
    dry_run: bool,
    changed_paths: list[str] | None = None,
    budget: int = 256,
    mncs_path: str | None = None,
) -> dict[str, Any]:
    """Run repository-domain remediation and return the mncs.remediation/1 envelope."""

    target = target.resolve()
    hints = changed_paths or []
    if budget < 1:
        return _refusal_envelope(target, dry_run, budget, "invalid-budget", "budget must be >= 1")
    bad_hint = _validate_hints(hints)
    if bad_hint is not None:
        return _refusal_envelope(
            target, dry_run, budget, "changed-path-invalid", f"changed path is not scope-relative: {bad_hint}"
        )
    if not target.is_dir():
        return _refusal_envelope(target, dry_run, budget, "checkout-missing", f"target is not a directory: {target}")
    run = _Run(target=target, dry_run=dry_run, hints=hints, budget=budget, mncs_path=_resolve_mncs(mncs_path))
    descriptors = sorted((target / "native-applications").glob("*.json")) if (target / "native-applications").is_dir() else []
    abi_cache: dict[str, tuple[str | None, str | None]] = {}
    for descriptor in descriptors:
        _check_descriptor(run, str(descriptor.relative_to(target)), abi_cache)
    _check_binding(run, abi_cache)
    identity_checks_wanted = bool(descriptors) or (run.target / "mncs_debug/generated/debug.py").is_file()
    if identity_checks_wanted and run.mncs_path is None:
        run.escalations.append(
            _Item(
                id=f"{PROVIDER_ID}:toolchain-missing",
                check="toolchain",
                path="",
                detail="no mncs toolchain available; identity coherence was not verified",
                severity="warning",
                action="provide an mncs executable with --mncs or MNCS, then re-run remediation",
            )
        )
    run.errors_before = sum(1 for item in (*run.repairs, *run.reconciliations) if item.severity == "error")
    run.errors_before += sum(1 for item in run.escalations if item.severity == "error")
    # Mutation (or dry-run mirroring) in dependency order: dead entries,
    # then stdlib entries, then identity refreezes and binding regeneration.
    ordered = sorted(
        (*run.repairs, *run.reconciliations),
        key=lambda item: (
            0 if item.id.startswith(f"{PROVIDER_ID}:dead-") else
            1 if item.id.startswith(f"{PROVIDER_ID}:missing-") else 2,
            item.id,
        ),
    )
    applied: list[_Item] = []
    for item in ordered:
        if len(applied) >= run.budget:
            run.exhausted = True
            run.escalations.append(
                _Item(
                    id=f"budget-exhausted:{target}",
                    check="budget",
                    path=item.path,
                    detail=f"budget of {run.budget} items exhausted; {len(ordered) - len(applied)} items deferred",
                    severity="warning",
                    action="re-run remediation to continue with the deferred items",
                )
            )
            break
        if run.dry_run:
            item.validated = False
            applied.append(item)
            continue
        try:
            ok = _apply_item(run, item)
        except (OSError, subprocess.SubprocessError, ValueError):
            ok = False
        item.validated = ok
        item.after = _fingerprint(run.target / item.path)
        if ok:
            run.items_done += 1
            applied.append(item)
        else:
            run.escalations.append(
                _Item(
                    id=f"{item.id}:failed",
                    check=item.check,
                    path=item.path,
                    detail=f"repair did not validate: {item.detail}",
                    severity="error",
                    action="inspect the failure, repair manually, then re-run remediation",
                )
            )
    # Items beyond the applied prefix (budget cut) leave the repairs list so
    # the envelope reports only what this run did or would do.
    applied_ids = {item.id for item in applied}
    run.repairs = [item for item in run.repairs if item.id in applied_ids]
    run.reconciliations = [item for item in run.reconciliations if item.id in applied_ids]
    repaired = sum(1 for item in run.repairs if item.validated)
    reconciled = sum(1 for item in run.reconciliations if item.validated)
    errors_after = run.errors_before
    if not run.dry_run:
        errors_after -= sum(1 for item in (*run.repairs, *run.reconciliations) if item.validated and item.severity == "error")
        errors_after += sum(1 for item in run.escalations if item.id.endswith(":failed") and item.severity == "error")
    blockers = sum(1 for item in run.escalations if item.severity == "error")
    degraded = sum(1 for item in run.escalations if item.severity != "error")
    if not run.dry_run:
        degraded += sum(1 for item in (*run.repairs, *run.reconciliations) if not item.validated)
    else:
        degraded += sum(1 for item in (*run.repairs, *run.reconciliations))
    remaining = [item.id for item in run.escalations[:64]]
    evidence: str | None = None
    artifact_dir = os.environ.get("MNCS_ENV_SESSION_ARTIFACT_DIR")
    if artifact_dir:
        try:
            directory = Path(artifact_dir)
            directory.mkdir(parents=True, exist_ok=True)
            evidence_path = directory / "mncs-debug-remediation.json"
            evidence_path.write_text(
                json.dumps(
                    {"provider": PROVIDER_ID, "target": target.as_posix(), "checks": run.checks},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            evidence = evidence_path.as_posix()
        except OSError:
            evidence = None
    return {
        "schema_version": REMEDIATION_SCHEMA,
        "provider": PROVIDER_ID,
        "provider_version": __version__,
        "scope": {"domain": "repository", "target": target.as_posix()},
        "dry_run": run.dry_run,
        "summary": {"repaired": repaired, "reconciled": reconciled, "degraded": degraded, "blockers": blockers},
        "remaining": remaining,
        "remaining_truncated": len(run.escalations) > 64,
        "repairs": [
            {
                "id": item.id,
                "class": item.repair_class or "safe_automatic",
                "provider": PROVIDER_ID,
                "target": item.path,
                "detail": item.detail,
                "before_fingerprint": item.before,
                "after_fingerprint": None if run.dry_run else item.after,
                "validated": item.validated,
            }
            for item in run.repairs
        ],
        "reconciliations": [
            {
                "id": item.id,
                "class": item.repair_class or "bounded_reconciliation",
                "provider": PROVIDER_ID,
                "target": item.path,
                "detail": item.detail,
                "before_fingerprint": item.before,
                "after_fingerprint": None if run.dry_run else item.after,
                "validated": item.validated,
            }
            for item in run.reconciliations
        ],
        "escalations": [
            {"id": item.id, "code": item.check, "target": item.path or None, "severity": item.severity, "action": item.action or item.detail}
            for item in run.escalations[:256]
        ],
        "evidence": evidence,
        "budget": {"max_items": run.budget, "items_done": run.items_done, "rounds": 1, "exhausted": run.exhausted},
        "validation": {
            "passed": errors_after == 0,
            "errors_before": run.errors_before,
            "errors_after": errors_after,
            "idempotent_known": True,
            "idempotent": True,
        },
    }


def crash_envelope(target: str, dry_run: bool, detail: str) -> dict[str, Any]:
    """Build a last-resort envelope when the provider itself fails."""

    return _refusal_envelope(Path(target) if target else Path("."), dry_run, 256, "provider-error", detail[:1024])


def _refusal_envelope(target: Path, dry_run: bool, budget: int, code: str, detail: str) -> dict[str, Any]:
    escalation_id = f"{PROVIDER_ID}:{code}"
    return {
        "schema_version": REMEDIATION_SCHEMA,
        "provider": PROVIDER_ID,
        "provider_version": __version__,
        "scope": {"domain": "repository", "target": target.as_posix()},
        "dry_run": dry_run,
        "summary": {"repaired": 0, "reconciled": 0, "degraded": 0, "blockers": 1},
        "remaining": [escalation_id],
        "remaining_truncated": False,
        "repairs": [],
        "reconciliations": [],
        "escalations": [{"id": escalation_id, "code": code, "severity": "error", "action": detail}],
        "evidence": None,
        "budget": {"max_items": max(budget, 1), "items_done": 0, "rounds": 0, "exhausted": False},
        "validation": {"passed": False, "errors_before": 1, "errors_after": 1, "idempotent_known": True, "idempotent": True},
    }
