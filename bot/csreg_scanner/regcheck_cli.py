#!/usr/bin/env python3
"""Standalone CLI to spot-check the registration checker against single servers.

This is a convenience tool for operators: it lets you run a registration check
locally, by hand, with the exact same behavior as the bot's scanner. It has no
role in the bot itself -- the plugin never invokes it -- so it is safe to omit
from a deployment. It exists purely so a human can reproduce, at a shell, the
verdict the scanner would produce for a given server.

Drop this next to resolver.py and regcheck.py (same directory) and run:

    python regcheck_cli.py matrix.org
    python regcheck_cli.py matrix.org continuwuity.rocks example.org
    python regcheck_cli.py --json matrix.org
    printf 'a.org\\nb.org\\n' | python regcheck_cli.py -    # read targets from stdin
    python regcheck_cli.py -v matrix.org                    # show resolution detail

Exit status is always 0 on completion (per-target failures surface as the
"unknown" status, never a crash) -- matching the scanner's contract.

This imports the real modules, so classification is exactly what the bot runs:
the verdict for any server matches the scanner's byte for byte. It does NOT
import the maubot plugin, so it has no maubot/mautrix/asyncpg dependencies;
only aiohttp + dnspython are needed.

One deliberate difference from the in-bot path: the scanner runs behind an
SSRF/IP-range filter (ipfilter.build_connector) because it acts on server names
that arrive untrusted from rooms. This CLI is only ever invoked manually by the
operator against targets they type themselves, so it uses a plain session with
no IP policy. The classification logic is identical; only that outbound guard,
which is a property of the bot's threat model rather than of the check itself,
is absent.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Optional

import aiohttp

# Import the real modules WITHOUT triggering the package __init__.
#
# The package's __init__.py does `from .bot import CSRegScanner`, which pulls in
# maubot/mautrix/asyncpg. We only need regcheck + resolver + fedversion +
# supportinfo, so we load those files DIRECTLY by path and never import the
# package itself -- this lets the CLI run on a dev machine that has only
# aiohttp + dnspython installed.
#
# regcheck.py, fedversion.py and supportinfo.py internally do
# `from .resolver import ...`; to satisfy that without package context we load
# resolver first, register it under the module name they expect, then load the
# siblings against it.
import importlib.util
import os
import types


def _load_sibling_modules():
    here = os.path.dirname(os.path.abspath(__file__))
    pkg_name = os.path.basename(here) or "csreg_scanner"

    # Create a lightweight package placeholder so relative imports
    # (`from .resolver import ...`) inside regcheck resolve to our files,
    # WITHOUT executing the real __init__.py.
    if pkg_name not in sys.modules:
        pkg = types.ModuleType(pkg_name)
        pkg.__path__ = [here]  # marks it as a package
        sys.modules[pkg_name] = pkg

    def _load(mod_basename: str):
        full_name = f"{pkg_name}.{mod_basename}"
        if full_name in sys.modules:
            return sys.modules[full_name]
        path = os.path.join(here, f"{mod_basename}.py")
        spec = importlib.util.spec_from_file_location(full_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_name] = module
        spec.loader.exec_module(module)
        return module

    resolver_mod = _load("resolver")   # load first; the siblings depend on it
    regcheck_mod = _load("regcheck")
    fedversion_mod = _load("fedversion")  # only needs resolver; no maubot/mautrix
    supportinfo_mod = _load("supportinfo")  # likewise resolver-only
    return regcheck_mod, resolver_mod, fedversion_mod, supportinfo_mod


_regcheck, _resolver, _fedversion, _supportinfo = _load_sibling_modules()
RegistrationChecker = _regcheck.RegistrationChecker
UNKNOWN = _regcheck.UNKNOWN
ServerResolver = _resolver.ServerResolver
ClientResolver = _resolver.ClientResolver
build_timeout = _resolver.build_timeout
read_json_capped = _resolver.read_json_capped
FederationVersionProbe = _fedversion.FederationVersionProbe
SupportInfoProbe = _supportinfo.SupportInfoProbe

_APP_ID = "net.codestorm.csreg-scanner"
_FALLBACK_VERSION = "0.1.13"


def _read_version() -> str:
    """Return the plugin version for --version.

    Reads the ``version`` field from maubot.yaml (one level up from this
    package directory) so the CLI stays in sync when the plugin is bumped.
    Falls back to a baked-in constant if the file is missing or unreadable
    (e.g. the CLI was copied out on its own). Parsed with a tiny line scan so
    we don't add a PyYAML dependency the bot doesn't otherwise need here.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    manifest = os.path.join(os.path.dirname(here), "maubot.yaml")
    try:
        with open(manifest, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("version:"):
                    value = stripped.split(":", 1)[1].strip().strip("'\"")
                    if value:
                        return value
    except OSError:
        pass
    return _FALLBACK_VERSION


def _build_client() -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        headers={"User-Agent": "csreg-scanner (registration scanner; +https://github.com/ll-SKY-ll/Matrix-federation-scanner)", "Accept": "application/json"},
        timeout=build_timeout(8.0),
        trust_env=False,
    )


async def _capture_register_flows(
    checker: "RegistrationChecker",
    target: str,
    client: aiohttp.ClientSession,
) -> dict:
    """Re-probe POST /_matrix/client/v3/register purely to surface the RAW UIA
    body for display -- the classifier consumes this internally and returns only
    a verdict, so the CLI repeats the probe to show what the server actually
    sent. Reuses the checker's own base-URL resolution and resolver's size cap /
    timeout so it hits the SAME endpoint under the SAME limits as a real scan.

    Returns a dict for display: {"base_url", "status", and either "flows" (the
    list of per-flow stage lists) or "note"/"error"}. Never raises.
    """
    info: dict = {}
    try:
        base_url, _wk = await checker._base_url(target)
    except Exception as e:  # noqa: BLE001
        return {"error": f"base-url resolution failed: {e}"}
    if base_url is None:
        return {"error": "unresolvable client base URL"}
    info["base_url"] = base_url

    url = f"{base_url}/_matrix/client/v3/register"
    try:
        async with client.post(
            url, json={},
            timeout=build_timeout(8.0),
            allow_redirects=False,
        ) as resp:
            info["status"] = resp.status
            body = await read_json_capped(resp)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        info["error"] = f"register probe failed: {e}"
        return info

    if not isinstance(body, dict):
        info["note"] = "no JSON object body (oversize, empty, or unparseable)"
        return info
    flows = body.get("flows")
    if not isinstance(flows, list):
        # e.g. a 403 M_FORBIDDEN body or a 400 M_UNRECOGNIZED -- show the errcode
        # so the verbose view explains WHY there were no flows.
        errcode = body.get("errcode")
        info["note"] = (
            f"no flows array (errcode={errcode})" if errcode
            else "no flows array in body"
        )
        return info
    # Each flow's `stages` list, verbatim, in order. Non-list stages are shown
    # as-is so a malformed flow is visible rather than silently normalized.
    info["flows"] = [
        f.get("stages") if isinstance(f, dict) else f for f in flows
    ]
    return info


async def check_one(
    target: str,
    client: aiohttp.ClientSession,
    log: logging.Logger,
    timeout: float,
    verbose: bool,
) -> dict:
    """Classify one target and (optionally) gather diagnostic detail for display.

    Returns a dict: {"target", "status", and when verbose: "client_base_url",
    "federation", "register" (raw UIA flows), "fed_version", "support"}.
    """
    out: dict = {"target": target}

    checker = RegistrationChecker(client, log)
    try:
        status = await asyncio.wait_for(checker.classify(target), timeout=timeout)
    except asyncio.TimeoutError:
        status = UNKNOWN
    except Exception as e:  # noqa: BLE001
        status = UNKNOWN
        out["error"] = f"{type(e).__name__}: {e}"
    out["status"] = status

    if verbose:
        # Resolution detail is informational only -- it does not affect the
        # status above. Gathered best-effort; failures are reported inline.
        try:
            ct = await ClientResolver(client).resolve(target)
            out["client_base_url"] = ct.base_url
        except Exception as e:  # noqa: BLE001
            out["client_base_url"] = f"<error: {e}>"
        try:
            fed = await ServerResolver(client).resolve(target)
            out["federation"] = fed.to_dict()
        except Exception as e:  # noqa: BLE001
            out["federation"] = {"error": str(e)}

        # Raw registration flows: what the server actually advertised, beyond
        # the single-word verdict. Same endpoint + caps as the real scan.
        out["register"] = await _capture_register_flows(checker, target, client)

        # Federation /version probe -- the same fed_name / fed_version that the
        # bot stores in the DB. Its probe owns a private verify-off session, so
        # build it here and close it after. authoritative mirrors the DB's
        # overwrite-vs-preserve flag.
        probe = FederationVersionProbe(client, log)
        try:
            fver = await asyncio.wait_for(probe.probe(target), timeout=timeout)
            out["fed_version"] = {
                "authoritative": fver.authoritative,
                "name": fver.name,
                "version": fver.version,
            }
        except asyncio.TimeoutError:
            out["fed_version"] = {"error": "timed out"}
        except Exception as e:  # noqa: BLE001
            out["fed_version"] = {"error": f"{type(e).__name__}: {e}"}
        finally:
            await probe.aclose()

        # Support well-known (/.well-known/matrix/support) -- the same fetcher
        # (and therefore the same authoritative-vs-no-signal contract) the full
        # scanner uses for storage: only a 200 with a JSON object counts, so
        # what prints here is exactly what the scanner would have written to
        # the support_info table. Rides the shared verifying session; nothing
        # to close. `document` carries the PARSED object so verbose --json
        # emits it as structured JSON, not a doubly-encoded string.
        support_probe = SupportInfoProbe(client, log)
        try:
            sup = await asyncio.wait_for(
                support_probe.fetch(target), timeout=timeout
            )
            out["support"] = {
                "authoritative": sup.authoritative,
                "document": (
                    json.loads(sup.raw_json) if sup.raw_json is not None else None
                ),
            }
        except asyncio.TimeoutError:
            out["support"] = {"error": "timed out"}
        except Exception as e:  # noqa: BLE001
            out["support"] = {"error": f"{type(e).__name__}: {e}"}

    return out


def _read_targets(args_targets: list[str]) -> list[str]:
    """Resolve the target list, expanding a lone '-' to stdin lines."""
    if args_targets == ["-"]:
        raw = sys.stdin.read().split()
        return [t.strip() for t in raw if t.strip()]
    return args_targets


# --- human-readable rendering ------------------------------------------------ #

# --- support well-known display rendering ---
# Lives HERE (not in supportinfo.py) on purpose: supportinfo.py is part of the
# public scanner repo, which must carry no rendering code (this CLI file is
# gitignored there). The private self-service bot carries its own mirror of
# this function -- if you touch one, touch the other.

# Per-line length cap for rendered display lines. Every value inside a support
# document is attacker-controlled up to the 64 KiB wire cap, so no single line
# may grow unbounded; real-world roles / mxids / emails / URLs are far shorter.
_SUPPORT_LINE_CAP = 200

# The spec'd schema of the support document. Keys OUTSIDE it (MSC extensions,
# custom fields) are rendered too -- every one of them, with their values, as
# their own key=value lines -- so nothing a server publishes is hidden; only
# the per-line length cap bounds them.
_SUPPORT_CONTACT_KEYS = ("role", "matrix_id", "email_address")
_SUPPORT_TOP_LEVEL_KEYS = frozenset({"contacts", "support_page"})


def _support_cap_line(line: str) -> str:
    if len(line) <= _SUPPORT_LINE_CAP:
        return line
    return line[:_SUPPORT_LINE_CAP] + "..."


def _support_fmt_value(value: object) -> str:
    """Single-line rendering of an unknown key's value: strings verbatim,
    containers as compact JSON (never multi-line), everything else str()."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _render_support_lines(
    doc: dict, max_contacts: Optional[int] = None
) -> list[str]:
    """Render a parsed support document as labelled key=value display lines.

    Returns UNINDENTED lines; the caller applies its own display indentation.
    Fields are rendered with their key names (not bare values), in the spec's
    schema order: ``support_page`` first, then ``contacts`` with each entry's
    role / matrix_id / email_address as ``key=value`` pairs. Keys outside the
    spec'd schema are rendered IN FULL -- as many as there are, values
    included: per-contact ones as indented ``key=value`` continuation lines
    under their entry, top-level ones as trailing ``key: value`` lines.
    Malformed shapes are annotated inline rather than dropped.

    ``max_contacts`` caps how many contact entries are rendered (the rest
    collapse to a ``... (+N more)`` line); None renders all. Every emitted
    line is length-capped (_SUPPORT_LINE_CAP). Never raises.
    """
    lines: list[str] = []

    sp = doc.get("support_page")
    if isinstance(sp, str) and sp:
        lines.append(_support_cap_line(f"support_page: {sp}"))
    elif "support_page" in doc:
        lines.append(_support_cap_line(f"support_page: (not a string: {sp!r})"))

    contacts = doc.get("contacts")
    if isinstance(contacts, list) and contacts:
        lines.append("contacts:")
        shown = contacts if max_contacts is None else contacts[:max_contacts]
        for i, c in enumerate(shown):
            if not isinstance(c, dict):
                lines.append(_support_cap_line(f"  [{i}] (malformed entry: {c!r})"))
                continue
            pairs = [
                f"{key}={c[key]}"
                for key in _SUPPORT_CONTACT_KEYS
                if c.get(key) is not None
            ]
            extra = sorted(k for k in c if k not in _SUPPORT_CONTACT_KEYS)
            if pairs:
                head = " ".join(pairs)
            else:
                head = "(no spec'd fields)" if extra else "(empty entry)"
            lines.append(_support_cap_line(f"  [{i}] {head}"))
            # Unknown per-contact keys: ALL of them, with values, one per
            # continuation line (own line so the entry line's cap can never
            # swallow them).
            for key in extra:
                lines.append(_support_cap_line(
                    f"      {key}={_support_fmt_value(c[key])}"
                ))
        hidden = len(contacts) - len(shown)
        if hidden > 0:
            lines.append(f"  ... (+{hidden} more)")
    elif "contacts" in doc:
        lines.append(_support_cap_line(
            f"contacts: (not a non-empty list: {type(contacts).__name__})"
        ))

    # Unknown top-level keys: ALL of them, with values, one per line.
    for key in sorted(k for k in doc if k not in _SUPPORT_TOP_LEVEL_KEYS):
        lines.append(_support_cap_line(
            f"{key}: {_support_fmt_value(doc[key])}"
        ))

    if not lines:
        lines.append("(empty document)")
    return lines


_COLOR = {
    "dangerously_open": "\033[1;31m",  # bold red
    "open": "\033[33m",                # yellow
    "oauth": "\033[36m",               # cyan
    "closed": "\033[32m",              # green
    "unknown": "\033[90m",             # grey
}
_RESET = "\033[0m"


def _fmt_status(status: str, use_color: bool) -> str:
    if use_color and status in _COLOR:
        return f"{_COLOR[status]}{status}{_RESET}"
    return status


def _print_human(result: dict, use_color: bool) -> None:
    target = result["target"]
    status = result["status"]
    print(f"{target:<40} {_fmt_status(status, use_color)}")
    if "error" in result:
        print(f"    error: {result['error']}")
    if "client_base_url" in result:
        print(f"    client base_url : {result['client_base_url']}")
    if "federation" in result:
        fed = result["federation"]
        if "error" in fed:
            print(f"    federation      : <error: {fed['error']}>")
        else:
            print(
                f"    federation      : {fed['host']}:{fed['port']} "
                f"(Host: {fed['host_header']}, SNI: {fed['tls_server_name']}, "
                f"via {fed['resolution_method']})"
            )
    if "fed_version" in result:
        fv = result["fed_version"]
        if "error" in fv:
            print(f"    fed version     : <error: {fv['error']}>")
        else:
            name = fv["name"] if fv["name"] is not None else "-"
            version = fv["version"] if fv["version"] is not None else "-"
            auth = "authoritative" if fv["authoritative"] else "non-authoritative"
            print(f"    fed version     : name={name} version={version} ({auth})")
    if "register" in result:
        reg = result["register"]
        base = reg.get("base_url")
        st = reg.get("status")
        head = "    register probe  :"
        meta = []
        if base is not None:
            meta.append(f"base_url={base}")
        if st is not None:
            meta.append(f"http={st}")
        print(f"{head} {' '.join(meta) if meta else ''}".rstrip())
        if "error" in reg:
            print(f"        error: {reg['error']}")
        elif "note" in reg:
            print(f"        {reg['note']}")
        elif "flows" in reg:
            if not reg["flows"]:
                print("        flows: (empty list)")
            else:
                print("        flows:")
                for i, stages in enumerate(reg["flows"]):
                    print(f"          [{i}] stages: {stages}")
    # Support well-known: LAST section by design (operator preference) -- it is
    # the least classification-relevant field and can be the longest.
    if "support" in result:
        sup = result["support"]
        if "error" in sup:
            print(f"    support         : <error: {sup['error']}>")
        elif not sup.get("authoritative"):
            print(
                "    support         : no document "
                "(non-200, non-JSON body, or fetch failed)"
            )
        else:
            print("    support         : (authoritative)")
            # Labelled key=value rendering (local _render_support_lines; the
            # private self-service bot carries a mirror). The CLI shows ALL
            # contacts (no count cap -- it's a terminal, and the full document
            # is the point of a spot check); per-line length caps still apply
            # inside the renderer. --json -v carries the full parsed document
            # regardless.
            doc = sup.get("document")
            if not isinstance(doc, dict):
                print(f"        (document not an object: {doc!r})")
            else:
                for ln in _render_support_lines(doc):
                    print(f"        {ln}")


async def _amain(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="regcheck_cli.py",
        description=(
            "Spot-check Matrix open-registration status for one or more "
            "servers, using the same classifier the scanner runs."
        ),
        epilog=(
            "examples:\n"
            "  regcheck_cli.py matrix.org\n"
            "  regcheck_cli.py --json matrix.org example.org\n"
            "  regcheck_cli.py -v matrix.org\n"
            "  printf 'a.org\\nb.org\\n' | regcheck_cli.py -\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{_APP_ID} {_read_version()}",
    )
    parser.add_argument(
        "targets", nargs="+",
        help="server name(s), e.g. matrix.org or matrix.org:8448; use '-' to read from stdin",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="emit JSON; default is {target: status} (scanner wire shape), but "
             "with -v it emits the full per-target object",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="also show resolved client base_url + federation target, the raw "
             "registration flows, the federation /version (name, version), and "
             "the support well-known document",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=20.0,
        help="total budget per target in seconds (default: 20)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI colour in human output",
    )
    parser.add_argument(
        "--debug", action="store_true", help="enable debug logging to stderr",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="[%(levelname)s %(name)s] %(message)s",
        stream=sys.stderr,
    )
    log = logging.getLogger("regcheck-cli")

    targets = _read_targets(args.targets)
    if not targets:
        print("no targets given", file=sys.stderr)
        return 0

    use_color = (not args.no_color) and sys.stdout.isatty()

    results: list[dict] = []
    async with _build_client() as client:
        # Sequential: this is a spot-check tool, not the bulk scanner. The bot
        # owns concurrency in production; here we keep output readable and
        # ordered.
        for target in targets:
            results.append(
                await check_one(target, client, log, args.timeout, args.verbose)
            )

    if args.json:
        if args.verbose:
            # Verbose JSON: the full per-target object (status + resolution +
            # raw flows + fed version + support doc), keyed by target. The
            # extra fields only exist because -v gathered them.
            print(json.dumps({r["target"]: r for r in results}, indent=2))
        else:
            # Default wire-shape map {target: status}, drop-in compatible with
            # the scanner's output contract.
            print(json.dumps({r["target"]: r["status"] for r in results}, indent=2))
    else:
        for r in results:
            _print_human(r, use_color)

    return 0


def main() -> None:
    sys.exit(asyncio.run(_amain()))


if __name__ == "__main__":
    main()
