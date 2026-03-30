# ========================= IMPORTS =========================
import re
import queue
import threading
import subprocess
import collections
import uuid
import logging
import time
import random

import requests
import urllib3
from bs4 import BeautifulSoup
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth
from urllib.parse import urljoin, urlparse, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="Web Audit Tool")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

# ========================= OPTIONAL DEPS =========================
try:
    from spellchecker import SpellChecker
    SPELLCHECK_AVAILABLE = True
except ImportError:
    SPELLCHECK_AVAILABLE = False

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except Exception:
    SPACY_AVAILABLE = False

# ========================= CONSTANTS =========================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
]

def random_ua():
    return random.choice(USER_AGENTS)

def get_headers(ua=None):
    ua = ua or random_ua()
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }

BASE_IGNORE = {
    "url", "html", "css", "js", "pdf", "http", "https", "www",
    "id", "ids", "api", "ui", "ux", "ok", "faq"
}

# ──────────────────────────────────────────────────────────────────────────────
# BLOCK PAGE DETECTION
#
# IMPORTANT: Be VERY conservative here.
# A login page (signin, authentication wall) is NOT broken — the link works,
# it just requires credentials. Only flag pages that are clearly CDN/WAF
# error pages where the destination server was never reached at all.
#
# Rule: only flag as block page if BOTH conditions are true:
#   1. The page body contains a known CDN error signature
#   2. The page has very little real content (< 2000 chars of visible text)
#      OR the title also matches a CDN error pattern
# ──────────────────────────────────────────────────────────────────────────────

# These signatures appear ONLY in CDN/WAF-generated error pages, never in
# real application pages.
CDN_ERROR_SIGNATURES = [
    "errors.edgesuite.net",                        # Akamai
    "Pardon Our Interruption",                     # Akamai
    "Request unsuccessful. Incapsula incident",    # Imperva/Incapsula
    "Ray ID:",                                     # Cloudflare (in error pages)
    "cf-error-details",                            # Cloudflare error page div
    "Checking your browser before accessing",      # Cloudflare challenge
    "Enable JavaScript and cookies to continue",   # Cloudflare/Akamai challenge
    "Please enable cookies.",                      # Cloudflare challenge
    "DDoS protection by",                          # Various CDN challenge pages
    "Attention Required! | Cloudflare",            # Cloudflare error title
]

# These title patterns indicate a true server error, NOT a login page.
# Be specific — do NOT include "login", "sign in", "unauthorized" etc.
CDN_ERROR_TITLE_PATTERNS = [
    r"^access\s+denied$",           # Exact "Access Denied" title only
    r"^403\s+forbidden$",           # Exact "403 Forbidden"
    r"^404\s+not\s+found$",         # Exact "404 Not Found"
    r"^500\s+",                     # 500 errors
    r"attention\s+required.*cloudflare",
    r"pardon\s+our\s+interruption",
]


def is_cdn_block_page(html: str) -> bool:
    """
    Return True ONLY if the page is a CDN/WAF-generated error page.
    Login pages, authentication walls, and real application pages
    with restricted access are NOT considered block pages.
    """
    if not html:
        return False

    lower = html.lower()

    # Check for CDN-specific body signatures (highly specific, low false-positive)
    for sig in CDN_ERROR_SIGNATURES:
        if sig.lower() in lower:
            log.debug(f"[block-detect] CDN signature matched: {sig!r}")
            return True

    # Check <title> for exact CDN error patterns
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if title_match:
        title = title_match.group(1).strip().lower()
        for pat in CDN_ERROR_TITLE_PATTERNS:
            if re.search(pat, title):
                log.debug(f"[block-detect] CDN title pattern matched: {pat!r} in {title!r}")
                return True

    return False


def effective_status(status_code: int, html: str) -> tuple:
    """
    Determine if a link is truly OK.

    A link is BROKEN only if:
      - HTTP status is 0 (connection failed) or >= 400 (server error), OR
      - HTTP status is 200-399 BUT the body is a CDN error page

    A link is OK if:
      - HTTP status is 200-399 AND body is not a CDN error page.
      - This includes login pages, paywalls, auth walls — those are reachable.
    """
    # Hard HTTP failure
    if status_code == 0 or status_code >= 400:
        return False, f"http:{status_code}"

    # Soft failure: CDN intercepted the request and returned a fake 200
    if is_cdn_block_page(html):
        return False, f"http:{status_code}+cdn-block"

    # Everything else: 200-399 with real content = OK
    return True, f"http:{status_code}"


# ========================= URL NORMALIZATION =========================
def normalize_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    clean_path = re.sub(r'/https?://.*', '', parsed.path)
    if not clean_path:
        clean_path = '/'
    return urlunparse(parsed._replace(path=clean_path, query='', fragment=''))


# ========================= TEXT EXTRACTION =========================
def extract_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "code", "pre"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


# ========================= SPELLCHECK =========================
def build_dynamic_ignore(raw_text, word_freq):
    dynamic_ignore = set(BASE_IGNORE)

    if SPACY_AVAILABLE:
        doc = nlp(raw_text[:1_000_000])
        for ent in doc.ents:
            for token in ent:
                dynamic_ignore.add(token.text.lower())
        for token in doc:
            if token.pos_ == "PROPN":
                dynamic_ignore.add(token.text.lower())

    for word, count in word_freq.items():
        if count >= 3:
            dynamic_ignore.add(word.lower())

    all_words_raw = re.findall(r"\b[a-zA-Z]{2,}\b", raw_text)
    case_forms = collections.defaultdict(set)
    for w in all_words_raw:
        case_forms[w.lower()].add(w)
    for lower, forms in case_forms.items():
        if all(f.isupper() or f.istitle() for f in forms):
            dynamic_ignore.add(lower)

    return dynamic_ignore


def check_spelling_from_text(raw_text: str):
    if not SPELLCHECK_AVAILABLE or not raw_text.strip():
        return []

    spell = SpellChecker()
    all_words = re.findall(r"\b[a-zA-Z]{3,}\b", raw_text)
    word_freq = collections.Counter(w.lower() for w in all_words)
    ignore = build_dynamic_ignore(raw_text, word_freq)

    candidates = [w for w in all_words if w.lower() not in ignore and not w.isupper()]
    misspelled = spell.unknown(candidates)

    results = []
    seen = set()
    for word in misspelled:
        if word in seen:
            continue
        seen.add(word)
        suggestion = spell.correction(word)
        if suggestion == word:
            continue
        pattern = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
        match = pattern.search(raw_text)
        if match:
            start = max(0, match.start() - 40)
            end = min(len(raw_text), match.end() + 40)
            snippet = raw_text[start:end].replace("\n", " ").strip()
            ctx = f"...{snippet}..."
        else:
            ctx = "(no context)"
        results.append({"word": word, "suggestion": suggestion, "context": ctx})

    return sorted(results, key=lambda x: x["word"])


# ========================= LINK EXTRACTION =========================
def extract_links_from_html(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for tag in soup.find_all(["a", "area"], href=True):
        href = tag.get("href", "").strip()
        if not href:
            continue
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "void")):
            continue
        full_url = urljoin(base_url, href)
        try:
            parsed = urlparse(full_url)
        except Exception:
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        if re.search(
            r"\.(pdf|jpg|jpeg|png|gif|svg|zip|rar|exe|mp4|mp3|doc|docx|xls|xlsx|ppt|pptx)(\?|$)",
            parsed.path, re.I
        ):
            continue
        urls.add(full_url)
    return sorted(urls)


# ========================= PAGE FETCH WITH FALLBACK =========================
def fetch_page_with_fallback(page_url: str, ctx=None):
    """
    Try requests → curl → Playwright to fetch a page.
    Returns: (html, strategy_used, blocked)
    """
    base_url = normalize_url(page_url)

    # ── Strategy A: requests ───────────────────────────────────────────────
    log.info(f"[fetch] requests → {base_url}")
    try:
        session = requests.Session()
        ua = random_ua()
        headers = get_headers(ua)
        session.head(base_url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        time.sleep(random.uniform(0.3, 0.8))
        resp = session.get(base_url, headers=headers, timeout=20, verify=False, allow_redirects=True)
        html = resp.text
        ok, reason = effective_status(resp.status_code, html)
        if ok:
            log.info(f"[fetch] requests OK ({reason})")
            return html, "requests", False
        log.warning(f"[fetch] requests not usable: {reason}")
    except Exception as e:
        log.warning(f"[fetch] requests exception: {e}")

    # ── Strategy B: curl ───────────────────────────────────────────────────
    log.info(f"[fetch] curl → {base_url}")
    try:
        ua = random_ua()
        result = subprocess.run([
            "curl", "-s", "-L", "-k",
            "--max-time", "30",
            "-A", ua,
            "-H", "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.9",
            "-H", "Accept-Encoding: gzip, deflate",
            "-H", "Connection: keep-alive",
            "--compressed",
            "-w", "\n__STATUS__%{http_code}",
            base_url
        ], capture_output=True, text=True, timeout=35)

        output = result.stdout
        status_match = re.search(r"__STATUS__(\d+)$", output)
        status_code = int(status_match.group(1)) if status_match else 0
        html = re.sub(r"\n__STATUS__\d+$", "", output)

        ok, reason = effective_status(status_code, html)
        if ok:
            log.info(f"[fetch] curl OK ({reason})")
            return html, "curl", False
        log.warning(f"[fetch] curl not usable: {reason}")
    except Exception as e:
        log.warning(f"[fetch] curl exception: {e}")

    # ── Strategy C: Playwright stealth ────────────────────────────────────
    if ctx is not None:
        log.info(f"[fetch] Playwright → {base_url}")
        try:
            page = ctx.new_page()
            Stealth().apply_stealth_sync(page)
            page.set_extra_http_headers({
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            })
            r = page.goto(base_url, wait_until="networkidle", timeout=45000)
            page.wait_for_selector("body", timeout=10000)
            page.evaluate("() => { window.scrollTo(0, document.body.scrollHeight / 2); }")
            page.wait_for_timeout(800)
            page.evaluate("() => { window.scrollTo(0, document.body.scrollHeight); }")
            page.wait_for_timeout(800)
            page.evaluate("() => { window.scrollTo(0, 0); }")
            page.wait_for_timeout(1000)

            status_code = r.status if r else 0
            html = page.content()
            page.close()

            ok, reason = effective_status(status_code, html)
            if ok:
                log.info(f"[fetch] Playwright OK ({reason})")
                return html, "playwright", False
            log.warning(f"[fetch] Playwright not usable: {reason}")
            return html, "playwright-blocked", True

        except Exception as e:
            log.error(f"[fetch] Playwright exception: {e}")
            try:
                page.close()
            except Exception:
                pass

    return None, "all-failed", True


# ========================= LINK CHECKING =========================
def is_broken(ctx, url):
    """
    Check whether a URL is broken.

    Broken = connection refused / timeout / HTTP 4xx-5xx / CDN error page.
    NOT broken = login page, paywall, auth redirect, any real page content.
    """
    all_details = []

    # ── Try requests ──────────────────────────────────────────────────────
    try:
        ua = random_ua()
        r = requests.get(url, headers=get_headers(ua), timeout=15,
                         allow_redirects=True, verify=False)
        ok, reason = effective_status(r.status_code, r.text)
        if ok:
            return False, f"requests:{reason}"
        all_details.append(f"requests:{reason}")
    except requests.exceptions.Timeout:
        all_details.append("requests:ERR(Timeout)")
    except requests.exceptions.ConnectionError:
        all_details.append("requests:ERR(ConnectionError)")
    except Exception as e:
        all_details.append(f"requests:ERR({e.__class__.__name__})")

    # ── Try curl (with body capture) ──────────────────────────────────────
    try:
        ua = random_ua()
        result = subprocess.run([
            "curl", "-s", "-L", "-k",
            "--max-time", "20",
            "-A", ua,
            "-w", "\n__STATUS__%{http_code}",
            url
        ], capture_output=True, text=True, timeout=25)

        output = result.stdout
        status_match = re.search(r"__STATUS__(\d+)$", output)
        status_code = int(status_match.group(1)) if status_match else 0
        body = re.sub(r"\n__STATUS__\d+$", "", output)

        ok, reason = effective_status(status_code, body)
        if ok:
            return False, f"curl:{reason}"
        all_details.append(f"curl:{reason}")
    except Exception as e:
        all_details.append(f"curl:ERR({e.__class__.__name__})")

    # ── Try Playwright (with body capture) ────────────────────────────────
    if ctx is not None:
        page = ctx.new_page()
        Stealth().apply_stealth_sync(page)
        try:
            r = page.goto(url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(1000)
            status_code = r.status if r else 0
            html = page.content()
            page.close()

            ok, reason = effective_status(status_code, html)
            if ok:
                return False, f"playwright:{reason}"
            all_details.append(f"playwright:{reason}")
        except Exception as e:
            try:
                page.close()
            except Exception:
                pass
            all_details.append(f"playwright:ERR({e.__class__.__name__})")
    else:
        all_details.append("playwright:skipped")

    return True, " | ".join(all_details)


# ========================= PLAYWRIGHT SETUP =========================
def make_browser_context(p):
    ua = random_ua()
    browser = p.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
        ]
    )
    ctx = browser.new_context(
        ignore_https_errors=True,
        user_agent=ua,
        viewport={"width": 1280, "height": 900},
        locale="en-US",
        timezone_id="America/New_York",
        java_script_enabled=True,
    )
    ctx.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        window.chrome = { runtime: {} };
    """)
    return browser, ctx


# ========================= EXTRA API ROUTES =========================

USER_DICT_FILE = "user_dictionary.txt"


def load_user_dict() -> set:
    try:
        with open(USER_DICT_FILE, "r") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in scans:
        return {"error": "Scan not found"}
    state = scans[scan_id]
    all_links = [lnk for r in state.get("results", []) for lnk in r.get("links", [])]
    broken = [lnk for lnk in all_links if lnk.get("broken")]
    return {
        "status": state.get("status"),
        "pages_done": state.get("pages_done", 0),
        "results": state.get("results", []),
        "metrics": {
            "total_links": len(all_links),
            "broken": len(broken),
            "ok_links": len(all_links) - len(broken),
        }
    }


@app.get("/api/dictionary")
def get_dictionary():
    return {"words": sorted(load_user_dict())}


@app.get("/api/capabilities")
def capabilities():
    return {
        "spellcheck": SPELLCHECK_AVAILABLE,
        "spacy": SPACY_AVAILABLE,
        "stealth": True,
    }


# ========================= WORKER =========================
def worker(work_q, result_q, run_spell, run_links):
    with sync_playwright() as p:
        browser, ctx = make_browser_context(p)
        try:
            while True:
                try:
                    page_url = work_q.get(timeout=3)
                except queue.Empty:
                    break

                try:
                    base_url = normalize_url(page_url)
                    log.info(f"[worker] Processing: {base_url}")

                    html, strategy, blocked = fetch_page_with_fallback(base_url, ctx)

                    if blocked or not html:
                        log.error(f"[worker] All strategies failed for: {base_url}")
                        result_q.put({
                            "type": "page_error",
                            "page_url": base_url,
                            "msg": (
                                f"Bot protection or access denied on all fetch strategies "
                                f"(last tried: {strategy})."
                            )
                        })
                        work_q.task_done()
                        continue

                    raw_text = extract_text_from_html(html)
                    typos = check_spelling_from_text(raw_text) if run_spell else []
                    links = extract_links_from_html(html, base_url) if run_links else []

                    log.info(
                        f"[worker] {base_url} | strategy={strategy} | "
                        f"typos={len(typos)} | links={len(links)}"
                    )

                    link_results = []
                    for link in links:
                        broken_flag, detail = is_broken(ctx, link)
                        link_results.append({"url": link, "broken": broken_flag, "detail": detail})
                        result_q.put({"type": "link_progress"})

                    result_q.put({
                        "type": "page_done",
                        "page_url": base_url,
                        "typos": typos,
                        "links": link_results,
                        "links_found": len(links),
                        "fetch_strategy": strategy,
                    })

                except Exception as ex:
                    log.error(f"[worker] Unexpected error on {page_url}: {ex}")
                    result_q.put({"type": "page_error", "page_url": page_url, "msg": str(ex)})
                finally:
                    work_q.task_done()
        finally:
            browser.close()


# ========================= SCAN STATE =========================

scans = {}


class ScanRequest(BaseModel):
    urls: list
    run_spell: bool = True
    run_links: bool = True
    num_workers: int = 3


@app.post("/api/scan/start")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "status": "running",
        "results": [],
        "pages_done": 0,
        "total_links_checked": 0,
    }
    background_tasks.add_task(run_scan, scan_id, req.urls, req.run_spell, req.run_links, req.num_workers)
    return {"scan_id": scan_id}


def drain_queue(result_q, scan_id):
    state = scans[scan_id]
    while True:
        msg = result_q.get()
        if msg["type"] == "page_done":
            state["pages_done"] += 1
            state["results"].append({
                "page_url": msg["page_url"],
                "typos": msg["typos"],
                "links": msg["links"],
                "fetch_strategy": msg.get("fetch_strategy", "unknown"),
            })
        elif msg["type"] == "link_progress":
            state["total_links_checked"] += 1
        elif msg["type"] == "page_error":
            state["pages_done"] += 1
            state["results"].append({
                "page_url": msg["page_url"],
                "typos": [],
                "links": [],
                "error": msg["msg"],
                "fetch_strategy": "failed",
            })
            log.error(f"[drain] Page error: {msg['page_url']} — {msg['msg']}")
        elif msg["type"] == "done":
            state["status"] = "done"
            break
        result_q.task_done()


def run_scan(scan_id, urls, run_spell, run_links, workers):
    result_q = queue.Queue()
    work_q = queue.Queue()

    normalized = [normalize_url(u) for u in urls]
    for u in normalized:
        log.info(f"[scan] Queuing: {u}")
        work_q.put(u)

    drain_thread = threading.Thread(
        target=drain_queue, args=(result_q, scan_id), daemon=True
    )
    drain_thread.start()

    threads = []
    for _ in range(min(workers, len(normalized))):
        t = threading.Thread(
            target=worker,
            args=(work_q, result_q, run_spell, run_links),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    result_q.put({"type": "done"})
    drain_thread.join()
    log.info(f"[scan] Scan {scan_id} complete.")


@app.get("/")
def serve_index():
    return FileResponse("static/index.html")