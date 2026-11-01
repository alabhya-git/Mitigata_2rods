"""Small reviewed CTF dialogue primitive. No eval, shell strings or arbitrary commands."""

from __future__ import annotations

import asyncio
import json
import operator
import re
import uuid
import zlib

from .codes import candidates
from .scope import ScopeDenied


# A closed library of checksum strategies a text protocol may demand. Each maps a
# (path, pid) pair to the token the service expects. No eval: every strategy is an
# explicit, reviewed arithmetic expression over documented inputs. The correct one is
# selected by matching the service's own worked example and, failing that, by trying
# each live and keeping whichever returns the resource.
def _ascii_sum(path: str) -> int:
    return sum(ord(c) for c in path)


CHECKSUM_STRATEGIES = {
    "ascii_sum_xor_pid_hex": lambda path, pid: format(_ascii_sum(path) ^ pid, "x"),
    "ascii_sum_xor_pid_dec": lambda path, pid: str(_ascii_sum(path) ^ pid),
    "ascii_sum_hex": lambda path, pid: format(_ascii_sum(path), "x"),
    "ascii_sum_dec": lambda path, pid: str(_ascii_sum(path)),
    "ascii_sum_plus_pid_hex": lambda path, pid: format(_ascii_sum(path) + pid, "x"),
    "len_xor_pid_hex": lambda path, pid: format(len(path) ^ pid, "x"),
    "crc32_hex": lambda path, pid: format(zlib.crc32(path.encode()) & 0xFFFFFFFF, "x"),
    "crc32_xor_pid_hex": lambda path, pid: format((zlib.crc32(path.encode()) ^ pid) & 0xFFFFFFFF, "x"),
}

# Command verbs we never send even if a service advertises them.
_UNSAFE_VERBS = {"DELETE", "DROP", "REMOVE", "DESTROY", "SHUTDOWN", "RESTART", "RESET", "PURGE", "KILL"}


def parse_commands(text: str) -> list[str]:
    """Uppercase command verbs advertised in a banner or HELP reference."""
    verbs = []
    for match in re.finditer(r"(?m)^\s*([A-Z][A-Z0-9_]{1,15})(?=\s|$)", text):
        verb = match.group(1)
        if verb not in verbs and verb not in {"HTTP", "GET", "POST", "PID", "ASCII", "XOR", "FLAG"}:
            verbs.append(verb)
    return verbs


def command_syntax(text: str, verb: str) -> list[str]:
    """Ordered ``<placeholder>`` names for a command's documented syntax line."""
    match = re.search(rf"(?m)^\s*{re.escape(verb)}\s+((?:<[^>]+>\s*)+)", text)
    if not match:
        return []
    return [p.lower() for p in re.findall(r"<([^>]+)>", match.group(1))]


def learn_checksum(text: str):
    """Pick the checksum strategy that reproduces the service's worked example, if any."""
    path = re.search(r'path\s+"([^"]{1,256})"', text)
    pid = re.search(r"\bpid\s+(\d{1,10})", text, re.IGNORECASE)
    expected = re.findall(r'(?:->|=)\s*"?(?:0x)?([0-9a-fA-F]{1,16})"?\s*$', text, re.MULTILINE)
    if not expected:
        expected = re.findall(r'->\s*"?(?:0x)?([0-9a-fA-F]{2,16})"?', text)
    if not (path and pid and expected):
        return None
    target = expected[-1].lower()
    example_path, example_pid = path.group(1), int(pid.group(1))
    for name, fn in CHECKSUM_STRATEGIES.items():
        try:
            if fn(example_path, example_pid).lower().removeprefix("0x") == target:
                return name
        except (ValueError, ZeroDivisionError):
            continue
    return None


def resource_hint(text: str) -> str | None:
    """A path the service itself names as the resource to request."""
    for pattern in (
        r"(?:request|req)\s+for\s+(/[A-Za-z0-9_./-]{1,128})",
        r"(?:resource|flag|file)\s+(?:is|at)\s+(/[A-Za-z0-9_./-]{1,128})",
        r"capture\s+(?:the\s+flag\s+)?(?:at\s+)?(/[A-Za-z0-9_./-]{1,128})",
        r'path[\'"\s:=]+(/[A-Za-z0-9_./-]{1,128})',
    ):
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.group(1) not in {"/abc", "/path", "/example"}:
            return match.group(1)
    return None


def session_pid(text: str) -> int | None:
    match = re.search(r"\bPID[:\s]+(\d{1,10})", text)
    return int(match.group(1)) if match else None


def arithmetic_answer(banner):
    match = re.search(
        rb"(?i)(?:calculate|compute|what is|solve)[:\s]*(-?\d{1,6})\s*([+*\-])\s*(-?\d{1,6})(?:\s|[?=]|$)",
        banner,
    )
    if not match:
        return None
    left, right = int(match.group(1)), int(match.group(3))
    value = {b"+": operator.add, b"-": operator.sub, b"*": operator.mul}[match.group(2)](left, right)
    return str(value).encode() + b"\n"


async def investigate_dialogue(agent, task):
    c = agent.ctx
    if not c.manifest.action_allowed("challenge_interaction"):
        raise ScopeDenied("Reviewed challenge interaction is not enabled")
    address, port = task["payload"]["address"], task["payload"]["port"]
    if not c.broker.guard.address_allowed(address, port):
        raise ScopeDenied("Challenge endpoint outside scope")
    await c.broker.reserve(action="tcp", operation="bounded_arithmetic_dialogue", address=address, port=port)
    request_id = uuid.uuid4().hex

    def operation():
        sock = c.broker._connect(request_id, address, port, min(3, c.manifest.budgets.timeout))
        transcript = []
        try:
            sock.settimeout(min(3, c.manifest.budgets.timeout))
            for _ in range(3):
                try:
                    incoming = sock.recv(8192)
                except TimeoutError:
                    break
                if not incoming:
                    break
                transcript.append({"direction": "received", "text": incoming.decode(errors="replace")})
                answer = arithmetic_answer(incoming)
                if answer is None:
                    break
                c.broker.audit(
                    "allowed", action="tcp", operation="arithmetic_answer", address=address, port=port
                )
                sock.sendall(answer)
                transcript.append({"direction": "sent", "text": answer.decode()})
            return transcript
        finally:
            c.broker._close(request_id)

    try:
        transcript = await asyncio.wait_for(
            asyncio.to_thread(operation), min(12, c.manifest.budgets.timeout * 3)
        )
    except (OSError, TimeoutError):
        c.ledger(
            agent.role,
            "network.challenge_dialogue",
            task["target"],
            "inconclusive",
            reason="dialogue_unavailable",
        )
        return
    ref = c.evidence.capture(
        c.run_id,
        json.dumps(transcript).encode(),
        kind="protocol_dialogue",
        metadata={"address": address, "port": port},
    )
    raw = "\n".join(t["text"] for t in transcript if t["direction"] == "received").encode()
    if candidates(raw, c.manifest.investigation.flag_patterns):
        data_ref = c.evidence.capture(
            c.run_id,
            raw,
            kind="protocol_received",
            metadata={"address": address, "port": port, "transcript": ref},
        )
        c.store.enqueue(
            c.run_id,
            role="Code",
            kind="capture",
            target=f"tcp://{address}:{port}",
            payload={"evidence_id": data_ref},
        )
    c.store.put(
        c.run_id,
        "observation",
        "dialogue:" + task["target"],
        {
            "type": "bounded_protocol_dialogue",
            "address": address,
            "port": port,
            "exchanges": len(transcript),
            "claim": "Reviewed arithmetic dialogue and received bytes recorded; no arbitrary service commands were sent.",
        },
        [ref],
        agent.role,
    )


async def unauth_banner_withholds_code(c, address, port, flag_patterns) -> bool:
    """Falsifier control: a fresh unauthenticated connection must not reveal the resource.

    Connects, reads the banner, and (if a HELP-like command is advertised) reads the
    reference, without ever authenticating. Returns True when no flag-shaped value is
    present — i.e. the resource is genuinely gated behind the authenticated exchange.
    """
    if not c.broker.guard.address_allowed(address, port):
        raise ScopeDenied("Protocol endpoint outside scope")
    await c.broker.reserve(action="tcp", operation="protocol_unauth_control", address=address, port=port)
    request_id = uuid.uuid4().hex
    timeout = min(3, c.manifest.budgets.timeout)

    def session():
        sock = c.broker._connect(request_id, address, port, timeout)
        received = b""
        try:
            sock.settimeout(timeout)
            try:
                received += sock.recv(16384)
            except (TimeoutError, OSError):
                return received
            for verb in ("HELP", "MENU", "COMMANDS", "USAGE"):
                if re.search(rf"(?m)^\s*{verb}\b", received.decode(errors="replace")):
                    sock.sendall(verb.encode() + b"\n")
                    try:
                        received += sock.recv(16384)
                    except (TimeoutError, OSError):
                        pass
                    break
            return received
        finally:
            c.broker._close(request_id)

    try:
        received = await asyncio.wait_for(asyncio.to_thread(session), min(12, c.manifest.budgets.timeout * 3))
    except (OSError, TimeoutError):
        return False
    c.evidence.capture(
        c.run_id, received, kind="protocol_control", metadata={"address": address, "port": port}
    )
    has_code = bool(candidates(received, flag_patterns)) or bool(
        re.search(rb"[A-Za-z0-9_]{3,}\{[^}\n]{3,}\}", received)
    )
    return not has_code


def _recovered_secrets(c):
    """Artifact-recovered passkeys available to the Recon role, newest first."""
    values = []
    for record in c.store.records(c.run_id, "recovered_secret"):
        try:
            revealed = c.store.reveal(c.run_id, record["data"]["secret_ref"], "Recon")
        except (KeyError, PermissionError, ValueError):
            continue
        value = revealed.get("value") or revealed.get("password") or revealed.get("exact_value")
        if value and value not in values:
            values.append(value)
    return values


async def investigate_protocol(agent, task):
    """Drive a service's own documented text protocol to reach a protected resource.

    Bounded and reviewed: commands are limited to the service's advertised vocabulary
    (minus a hard denylist of mutating verbs), the passkey must be an artifact-recovered
    value (never invented), and the checksum formula is learned from the service's own
    worked example or discovered by trying the closed strategy library live. Everything
    received is scanned for flag candidates and handed to the Code verifier.
    """
    c = agent.ctx
    # Explicit opt-in only; otherwise fall back to the reviewed arithmetic dialogue so
    # the reference lab and demo behaviour are unchanged.
    if "protocol_scripting" not in c.manifest.allowed_actions:
        return await investigate_dialogue(agent, task)
    address, port = task["payload"]["address"], task["payload"]["port"]
    if not c.broker.guard.address_allowed(address, port):
        raise ScopeDenied("Protocol endpoint outside scope")
    case_key = "protocol:" + task["target"]
    existing = c.store.get(c.run_id, "protocol_session", case_key)
    if existing and existing["data"].get("complete"):
        return
    denied = {s.upper() for s in c.manifest.investigation.denied_action_segments} | _UNSAFE_VERBS
    secrets = _recovered_secrets(c)
    await c.broker.reserve(action="tcp", operation="reviewed_protocol_dialogue", address=address, port=port)
    request_id = uuid.uuid4().hex
    timeout = min(3, c.manifest.budgets.timeout)
    max_sends = min(16, max(4, c.manifest.budgets.max_auth_attempts))

    def session():
        sock = c.broker._connect(request_id, address, port, timeout)
        transcript = []
        try:
            sock.settimeout(timeout)

            def recv():
                # Slow, line-buffered services send a response in several laggy chunks and
                # end it with a prompt ("zone> ", "$ ", "# "). A single recv() desyncs the
                # dialogue (a later recv then picks up an earlier command's output). So wait
                # up to the full timeout for the first bytes, then keep draining until a
                # prompt tail appears or the socket goes idle.
                buf = b""
                sock.settimeout(timeout)
                try:
                    first = sock.recv(16384)
                except (TimeoutError, OSError):
                    return ""
                if not first:
                    return ""
                buf += first
                sock.settimeout(0.6)
                while not re.search(rb"[>$#]\s*$", buf):
                    try:
                        more = sock.recv(16384)
                    except (TimeoutError, OSError):
                        break
                    if not more:
                        break
                    buf += more
                text = buf.decode(errors="replace")
                if text:
                    transcript.append({"direction": "received", "text": text})
                return text

            def send(line):
                verb = line.split(" ", 1)[0].upper()
                if verb in denied:
                    return
                c.broker.audit(
                    "allowed", action="tcp", operation="protocol_command", address=address, port=port
                )
                sock.sendall(line.encode() + b"\n")
                transcript.append({"direction": "sent", "text": line})

            banner = recv()
            vocab = set(parse_commands(banner))
            sends = 0
            flags = {"auth_present": False, "auth_attempted": False}
            # Learn the protocol reference if a HELP-like command is advertised.
            help_text = ""
            help_verb = next((v for v in ("HELP", "MENU", "COMMANDS", "USAGE") if v in vocab), None)
            if help_verb:
                send(help_verb)
                sends += 1
                help_text = recv()
                vocab |= set(parse_commands(help_text))
            spec = banner + "\n" + help_text
            # Authenticate with each artifact-recovered passkey until one is accepted.
            auth_verb = next((v for v in ("AUTH", "LOGIN", "KEY", "PASS", "UNLOCK") if v in vocab), None)
            flags["auth_present"] = auth_verb is not None
            authed_text = ""
            if auth_verb:
                for secret in secrets[: max(1, max_sends - sends - 4)]:
                    if sends >= max_sends:
                        break
                    send(f"{auth_verb} {secret}")
                    flags["auth_attempted"] = True
                    sends += 1
                    reply = recv()
                    authed_text += "\n" + reply
                    if re.search(r"(?i)granted|accepted|welcome|success|authenticated|\bPID\b", reply):
                        break
            combined = spec + "\n" + authed_text
            # If a HELP only appears meaningfully after auth, (re)read it.
            if help_verb and "pid" not in combined.lower() and sends < max_sends:
                send(help_verb)
                sends += 1
                more = recv()
                combined += "\n" + more
                spec += "\n" + more
            # Compose a resource request if the protocol documents one.
            request_verb = None
            placeholders = []
            for verb in vocab:
                ph = command_syntax(spec, verb)
                if ph and any("path" in p or "resource" in p or "file" in p for p in ph):
                    request_verb, placeholders = verb, ph
                    break
            target_path = resource_hint(combined)
            pid = session_pid(combined)
            if request_verb and target_path:
                strategy = learn_checksum(combined)
                names = [strategy] if strategy else list(CHECKSUM_STRATEGIES)
                for name in names:
                    if sends >= max_sends:
                        break
                    try:
                        checksum = CHECKSUM_STRATEGIES[name](target_path, pid or 0)
                    except (ValueError, ZeroDivisionError):
                        continue
                    args = []
                    for ph in placeholders:
                        if "pid" in ph and pid is not None:
                            args.append(str(pid))
                        elif "path" in ph or "resource" in ph or "file" in ph:
                            args.append(target_path)
                        elif any(k in ph for k in ("crc", "sum", "hash", "check", "token", "sig")):
                            args.append(checksum)
                        else:
                            args.append(target_path)
                    send(f"{request_verb} " + " ".join(args))
                    sends += 1
                    reply = recv()
                    if re.search(r"(?i)\bflag\b|granted|authorized|\[\+\]", reply) and re.search(
                        r"[A-Za-z0-9_]{3,}\{", reply
                    ):
                        break
                    if candidates(reply.encode(), c.manifest.investigation.flag_patterns):
                        break
            return transcript, flags
        finally:
            c.broker._close(request_id)

    try:
        transcript, flags = await asyncio.wait_for(
            asyncio.to_thread(session), min(20, c.manifest.budgets.timeout * 4 + 2)
        )
    except (OSError, TimeoutError):
        c.ledger(agent.role, "network.protocol_session", task["target"], "inconclusive", reason="unavailable")
        return
    ref = c.evidence.capture(
        c.run_id,
        json.dumps(transcript).encode(),
        kind="protocol_dialogue",
        metadata={"address": address, "port": port},
    )
    received = "\n".join(t["text"] for t in transcript if t["direction"] == "received").encode()
    captured = bool(candidates(received, c.manifest.investigation.flag_patterns)) or bool(
        re.search(rb"[A-Za-z0-9_]{3,}\{[^}\n]{3,}\}", received)
    )
    # A session only blocks future runs once it is complete: it captured the resource, had
    # no auth gate, or already tried the available passkeys. If an auth gate was present
    # but no passkey existed yet, leave it open so a later artifact recovery can retry.
    complete = captured or not flags["auth_present"] or flags["auth_attempted"]
    c.store.put(
        c.run_id,
        "protocol_session",
        case_key,
        {
            "type": "reviewed_protocol_session",
            "address": address,
            "port": port,
            "exchanges": len(transcript),
            "complete": complete,
            "commands_sent": [t["text"].split(" ", 1)[0] for t in transcript if t["direction"] == "sent"],
            "claim": "Only service-advertised commands were sent; passkeys were artifact-recovered, not invented.",
        },
        [ref],
        agent.role,
    )
    if captured:
        # Driving the service's protocol to obtain the resource is the exploitation step.
        c.store.event(
            c.run_id, agent.role, "protocol_resource_obtained",
            {"address": address, "port": port}, phase="Exploitation",
        )
        data_ref = c.evidence.capture(
            c.run_id,
            received,
            kind="protocol_received",
            metadata={"address": address, "port": port, "transcript": ref},
        )
        # Propose the protocol-capture finding; the Falsifier replays the documented
        # exchange and requires the resource to appear only after the full handshake.
        if "network.protocol_resource_capture" in c.manifest.permitted_checks:
            c.candidate(
                agent.role,
                c.checks.recipes["network.protocol_resource_capture"],
                task["target"],
                [ref, data_ref],
                address=address,
                port=port,
                transcript_evidence=ref,
                received_evidence=data_ref,
            )
        c.store.enqueue(
            c.run_id,
            role="Code",
            kind="capture",
            target=f"tcp://{address}:{port}",
            payload={"evidence_id": data_ref},
        )
