"""One reviewed credential offer; anonymous and invalid-session controls prove access."""

from __future__ import annotations

import uuid
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit

from .extractors import equivalent_response, parse_page
from .scope import ScopeDenied


def password_form(response):
    for form in parse_page(response.text).forms:
        if form["method"] == "POST" and sum(f["type"] == "password" for f in form["fields"]) == 1:
            return form
    return None


async def verify_form(c, data):
    details = data["details"]
    prerequisite = c.store.by_id(c.run_id, details["binary_finding"])
    if not prerequisite or prerequisite["data"]["status"] != "confirmed":
        raise ValueError("Artifact credential prerequisite is not confirmed")
    credential = c.store.reveal(c.run_id, details["secret_ref"], "Falsifier")
    before = await c.broker.http(data["target"])
    form = password_form(before)
    if form is None:
        raise ValueError("No supported password form is currently present")
    login_url = c.broker.guard.destination(urljoin(before.url, form["action"])).url
    if urlsplit(login_url).netloc != urlsplit(credential["service_url"]).netloc:
        raise ScopeDenied("Credential cannot be offered to another authority")
    password = next(f["name"] for f in form["fields"] if f["type"] == "password")
    user = next(
        (
            f["name"]
            for f in form["fields"]
            if f["type"] in {"text", "email"} and f["name"].lower() in {"username", "user", "email", "login"}
        ),
        None,
    )
    if user is None:
        raise ValueError("Username field is ambiguous; no credential offered")
    fields = {f["name"]: f.get("value", "") for f in form["fields"] if f["type"] == "hidden"}
    fields.update({user: credential["username"], password: credential["password"]})
    accepted = await c.broker.submit_login(login_url, fields)
    cookies = SimpleCookie()
    cookies.load(accepted.headers.get("set-cookie", ""))
    host = urlsplit(login_url).hostname
    selected = {k: v for k, v in cookies.items() if not v["domain"] or v["domain"].lstrip(".") == host}
    if not selected:
        raise ValueError("Authentication did not return a supported same-authority session cookie")
    cookie = "; ".join(k + "=" + v.value for k, v in selected.items())
    protected = c.broker.guard.destination(
        urljoin(login_url, accepted.headers.get("location", data["target"]))
    ).url
    if urlsplit(protected).netloc != urlsplit(login_url).netloc:
        raise ScopeDenied("Cross-authority session redirect blocked")
    anonymous = await c.broker.http(protected)
    invalid = await c.broker.http(
        protected,
        credential={"cookie": "; ".join(k + "=mitigata_invalid_" + uuid.uuid4().hex for k in selected)},
    )
    positive = await c.broker.http(protected, credential={"cookie": cookie})
    challenged = lambda r: r.status in {401, 403} or password_form(r) is not None
    controls = {
        "anonymous_challenged": challenged(anonymous),
        "invalid_session_challenged": challenged(invalid),
        "valid_session_accepted": 200 <= positive.status < 300 and not challenged(positive),
        "different_from_anonymous": not equivalent_response(anonymous, positive),
        "complete_responses": not any(r.truncated for r in (accepted, anonymous, invalid, positive)),
    }
    evidence = [r.evidence_id for r in (before, accepted, anonymous, invalid, positive)]
    if not all(controls.values()):
        return {
            "status": "rejected",
            "reason": "The credential did not establish a controlled protected-resource boundary",
            "controls": controls,
            "evidence": evidence,
        }
    session = c.store.secret(c.run_id, {"cookie": cookie, "service_url": protected})
    return {
        "status": "confirmed",
        "reason": "Only the artifact-derived session retrieves the protected resource; anonymous and invalid-session controls are challenged",
        "controls": controls,
        "evidence": evidence,
        "session_ref": session,
        "protected_url": protected,
    }
