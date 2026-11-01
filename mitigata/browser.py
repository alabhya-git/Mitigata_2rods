"""Rendered discovery with all page HTTP requests fulfilled by the scoped broker."""

from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .runtime_guard import tool_launch_permit
from .scope import ScopeDenied
from .transport import Response


async def render_page(agent, task):
    c = agent.ctx
    if sys.platform != "linux" or c.manifest.execution_profile != "linux_confined":
        c.store.put(
            c.run_id,
            "capability",
            "browser",
            {"available": False, "reason": "Rendered live discovery requires Linux kernel confinement"},
            role=agent.role,
        )
        return
    try:
        from playwright._impl._driver import compute_driver_executable
        from playwright.async_api import async_playwright
    except ImportError:
        c.store.put(
            c.run_id,
            "capability",
            "browser",
            {"available": False, "reason": "Playwright is not installed"},
            role=agent.role,
        )
        return
    chrome = (
        os.environ.get("MITIGATA_CHROME_PATH") or shutil.which("chromium") or shutil.which("google-chrome")
    )
    if not chrome:
        c.store.put(
            c.run_id,
            "capability",
            "browser",
            {"available": False, "reason": "Chromium is not installed"},
            role=agent.role,
        )
        return
    driver, entrypoint = compute_driver_executable()
    permit = tool_launch_permit.set((str(driver), str(entrypoint), "run-driver"))
    try:
        playwright = await async_playwright().start()
    finally:
        tool_launch_permit.reset(permit)
    browser = None
    refs = []
    count = 0
    try:
        browser = await playwright.chromium.launch(
            executable_path=chrome,
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--disable-extensions",
            ],
            env={"PATH": os.environ.get("PATH", ""), "HOME": "/tmp", "LANG": "C.UTF-8"},
        )
        context = await browser.new_context(service_workers="block", accept_downloads=False)
        if not hasattr(context, "route_web_socket"):
            raise ValueError("Browser version cannot enforce WebSocket blocking")

        async def block_websocket(socket):
            await socket.close()

        await context.route_web_socket("**/*", block_websocket)

        async def route(request_route):
            nonlocal count
            request = request_route.request
            count += 1
            if request.method != "GET" or count > min(60, c.manifest.budgets.max_pages):
                await request_route.abort()
                return
            try:
                response = await c.broker.http(request.url, follow_redirects=False)
                refs.append(response.evidence_id)
                headers = {
                    k: v
                    for k, v in response.headers.items()
                    if k
                    not in {
                        "content-encoding",
                        "content-length",
                        "transfer-encoding",
                        "connection",
                        "set-cookie",
                    }
                }
                await request_route.fulfill(status=response.status, headers=headers, body=response.body)
                if response.status < 400 and any(
                    x in response.headers.get("content-type", "") for x in ("json", "javascript")
                ):
                    await agent.consume(response, 1)
            except (OSError, TimeoutError, ValueError):
                await request_route.abort()

        await context.route("**/*", route)
        page = await context.new_page()
        navigation = await page.goto(
            task["target"],
            wait_until="domcontentloaded",
            timeout=min(30000, int(c.manifest.budgets.timeout * 4000)),
        )
        await page.wait_for_timeout(750)
        c.broker.guard.destination(page.url)
        whole = (await page.content()).encode()
        truncated = len(whole) > c.manifest.budgets.max_body_bytes
        raw = whole[: c.manifest.budgets.max_body_bytes]
        status = navigation.status if navigation else 200
        ref = c.evidence.capture(
            c.run_id,
            raw,
            kind="browser_dom",
            metadata={
                "url": page.url,
                "status": status,
                "truncated": truncated,
                "headers": {"content-type": "text/html"},
                "requests": count,
                "source_evidence": refs[:60],
            },
        )
        await agent.consume(
            Response(page.url, status, {"content-type": "text/html"}, raw, ref, truncated=truncated), 1
        )
        c.store.put(
            c.run_id,
            "capability",
            "browser",
            {
                "available": True,
                "requests_brokered": count,
                "service_workers": "blocked",
                "websockets": "blocked",
            },
            [ref],
            agent.role,
        )
    except Exception as exc:  # noqa: BLE001 - record optional runtime failure without inventing successful coverage
        c.store.put(
            c.run_id,
            "capability",
            "browser",
            {
                "available": False,
                "last_execution": "failed",
                "reason": f"{type(exc).__name__}: {str(exc)[:300]}",
            },
            role=agent.role,
        )
    finally:
        if browser:
            await browser.close()
        await playwright.stop()


async def prove_reflected_xss(c, url, fields):
    if (
        sys.platform != "linux"
        or c.manifest.execution_profile != "linux_confined"
        or not c.manifest.investigation.browser
    ):
        raise ScopeDenied("Executable XSS verification requires the confined browser profile")
    if not c.manifest.action_allowed("input_reflection"):
        raise ScopeDenied("Input verification is not permitted")
    from playwright._impl._driver import compute_driver_executable
    from playwright.async_api import async_playwright

    chrome = os.environ.get("MITIGATA_CHROME_PATH") or shutil.which("chromium")
    if not chrome:
        raise ValueError("Confined Chromium is unavailable")
    driver, entrypoint = compute_driver_executable()
    permit = tool_launch_permit.set((str(driver), str(entrypoint), "run-driver"))
    try:
        playwright = await async_playwright().start()
    finally:
        tool_launch_permit.reset(permit)
    browser = None
    refs = []
    try:
        browser = await playwright.chromium.launch(
            executable_path=chrome,
            headless=True,
            args=["--no-sandbox", "--disable-background-networking", "--disable-component-update"],
            env={"PATH": os.environ.get("PATH", ""), "HOME": "/tmp", "LANG": "C.UTF-8"},
        )
        context = await browser.new_context(service_workers="block", accept_downloads=False)

        async def block_socket(route):
            await route.close()

        await context.route_web_socket("**/*", block_socket)

        async def broker_route(route):
            if route.request.method != "GET":
                await route.abort()
                return
            try:
                response = await c.broker.http(route.request.url, follow_redirects=False)
                refs.append(response.evidence_id)
                headers = {
                    k: v
                    for k, v in response.headers.items()
                    if k in {"content-type", "content-security-policy", "location"}
                }
                await route.fulfill(status=response.status, headers=headers, body=response.body)
            except (ValueError, OSError, TimeoutError):
                await route.abort()

        await context.route("**/*", broker_route)
        page = await context.new_page()
        nonce = "proof_" + uuid.uuid4().hex
        parts = urlsplit(url)

        def probe_url(value):
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            query.update({field: value for field in fields[:3]})
            return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

        await page.goto(probe_url("mitigata_benign_" + nonce), wait_until="domcontentloaded", timeout=15000)
        baseline = await page.evaluate("() => window.__mitigataProof || null")
        payload = "<svg onload=\"window.__mitigataProof='" + nonce + "'\">"
        await page.goto(probe_url(payload), wait_until="domcontentloaded", timeout=15000)
        await page.wait_for_timeout(200)
        positive = await page.evaluate("() => window.__mitigataProof || null")
        controls = {
            "benign_control_did_not_execute": baseline is None,
            "controlled_script_executed": positive == nonce,
            "marker_only_payload": True,
            "no_external_callback": True,
        }
        ref = c.evidence.capture(
            c.run_id,
            json.dumps(controls).encode(),
            kind="browser_execution_control",
            metadata={"url": url, "fields": fields, "source_evidence": refs},
        )
        return controls, [*refs, ref]
    finally:
        if browser:
            await browser.close()
        await playwright.stop()
