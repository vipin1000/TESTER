# ========================= IMPORTS =========================
import re
import csv
import io
import queue
import threading
import subprocess
import collections
import uuid
import logging
import time
import random
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
from bs4 import BeautifulSoup
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
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

# ========================= OLLAMA CONFIG =========================
OLLAMA_URL   = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.2:3b"
LLM_CHUNK_SIZE = 3000

# ========================= CRAWLER / LINK-CHECK LIMITS =========================
DEFAULT_MAX_PAGES  = 50
DEFAULT_MAX_DEPTH  = 3
CRAWL_RATE_DELAY   = 0.5   # seconds between requests to the same domain
LINK_CHECK_WORKERS = 8     # parallel threads for link checking
LINK_CHECK_TIMEOUT = 12    # seconds per link check

# ========================= OPTIONAL DEPS =========================
try:
    from spellchecker import SpellChecker
    SPELLCHECK_FALLBACK_AVAILABLE = True
except ImportError:
    SPELLCHECK_FALLBACK_AVAILABLE = False

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

CDN_ERROR_SIGNATURES = [
    "errors.edgesuite.net", "Pardon Our Interruption",
    "Request unsuccessful. Incapsula incident", "Ray ID:",
    "cf-error-details", "Checking your browser before accessing",
    "Enable JavaScript and cookies to continue", "Please enable cookies.",
    "DDoS protection by", "Attention Required! | Cloudflare",
]

CDN_ERROR_TITLE_PATTERNS = [
    r"^access\s+denied$", r"^403\s+forbidden$", r"^404\s+not\s+found$",
    r"^500\s+", r"attention\s+required.*cloudflare", r"pardon\s+our\s+interruption",
]

def is_cdn_block_page(html: str) -> bool:
    if not html:
        return False
    lower = html.lower()
    for sig in CDN_ERROR_SIGNATURES:
        if sig.lower() in lower:
            return True
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if title_match:
        title = title_match.group(1).strip().lower()
        for pat in CDN_ERROR_TITLE_PATTERNS:
            if re.search(pat, title):
                return True
    return False

def effective_status(status_code: int, html: str) -> tuple:
    if status_code == 0 or status_code >= 400:
        return False, f"http:{status_code}"
    if is_cdn_block_page(html):
        return False, f"http:{status_code}+cdn-block"
    return True, f"http:{status_code}"


# ========================= URL HELPERS =========================
def normalize_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    clean_path = re.sub(r'/https?://.*', '', parsed.path)
    if not clean_path:
        clean_path = '/'
    if clean_path != '/' and clean_path.endswith('/'):
        clean_path = clean_path.rstrip('/')
    return urlunparse(parsed._replace(path=clean_path, query='', fragment=''))

def get_domain(url: str) -> str:
    return urlparse(url).netloc


# ========================= TEXT EXTRACTION =========================
def extract_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "code", "pre"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


# ========================= LLM SPELLCHECK =========================
SPELLCHECK_SYSTEM_PROMPT = """You are a precise spell-checker for website content.

Your job:
1. Read the text provided by the user.
2. Find words that are GENUINELY misspelled — wrong spelling of a real English word.
3. Ignore: proper nouns, brand names, acronyms, technical terms, domain names, URLs,
   codes/IDs, non-English words, and words that are simply uncommon.
4. For each misspelling, return a short surrounding context snippet (<= 80 chars).

Respond ONLY with a JSON array. No explanation, no markdown, no extra text.
Each item must have exactly these keys:
  "word"       - the misspelled word as it appears in the text
  "suggestion" - your best correct spelling
  "context"    - a short excerpt from the text showing the word in context

If there are no misspellings, respond with exactly: []
"""

def check_spelling_llm_chunk(chunk: str) -> list:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SPELLCHECK_SYSTEM_PROMPT},
            {"role": "user",   "content": f"Check this text for spelling errors:\n\n{chunk}"}
        ],
        "stream": False,
        "options": {"temperature": 0, "num_predict": 1024},
    }
    resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
    resp.raise_for_status()
    raw = resp.json().get("message", {}).get("content", "").strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.I)
    raw = re.sub(r"\s*```$", "", raw).strip()
    if not raw or raw == "[]":
        return []
    findings = json.loads(raw)
    valid = []
    for item in findings:
        if isinstance(item, dict) and "word" in item and "suggestion" in item:
            valid.append({
                "word":       str(item["word"]),
                "suggestion": str(item.get("suggestion", "")),
                "context":    str(item.get("context", "(no context)")),
            })
    return valid


def check_spelling_from_text(raw_text: str) -> list:
    if not raw_text.strip():
        return []
    chunks = []
    step = LLM_CHUNK_SIZE - 200
    for i in range(0, len(raw_text), step):
        chunks.append(raw_text[i: i + LLM_CHUNK_SIZE])
    log.info(f"[spell] {len(raw_text)} chars in {len(chunks)} chunk(s)")
    all_findings: dict = {}
    for idx, chunk in enumerate(chunks):
        try:
            findings = check_spelling_llm_chunk(chunk)
            for f in findings:
                w = f["word"].lower()
                if w not in all_findings:
                    all_findings[w] = f
        except requests.exceptions.ConnectionError:
            log.error("[spell] Ollama not reachable. Falling back.")
            return _fallback_spellcheck(raw_text)
        except requests.exceptions.Timeout:
            log.warning(f"[spell] Ollama timed out on chunk {idx+1}. Skipping.")
        except (json.JSONDecodeError, Exception) as e:
            log.warning(f"[spell] Error on chunk {idx+1}: {e}. Skipping.")
    return sorted(all_findings.values(), key=lambda x: x["word"])


# ========================= FALLBACK SPELLCHECK =========================
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


def _fallback_spellcheck(raw_text: str) -> list:
    if not SPELLCHECK_FALLBACK_AVAILABLE:
        return []
    spell     = SpellChecker()
    all_words = re.findall(r"\b[a-zA-Z]{3,}\b", raw_text)
    word_freq = collections.Counter(w.lower() for w in all_words)
    ignore    = build_dynamic_ignore(raw_text, word_freq)
    candidates = [w for w in all_words if w.lower() not in ignore and not w.isupper()]
    misspelled = spell.unknown(candidates)
    results, seen = [], set()
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
            end   = min(len(raw_text), match.end() + 40)
            ctx   = f"...{raw_text[start:end].replace(chr(10), ' ').strip()}..."
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
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "void")):
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
        urls.add(normalize_url(full_url))
    return sorted(urls)


# ========================= FAST LINK CHECKER =========================
def check_link_fast(url: str) -> tuple:
    """HEAD -> GET fallback. No Playwright. ~3s vs 20s per link."""
    headers = get_headers()

    # Try HEAD first
    try:
        r = requests.head(url, headers=headers, timeout=LINK_CHECK_TIMEOUT,
                          allow_redirects=True, verify=False)
        if r.status_code == 405:
            pass  # server doesn't support HEAD, fall through to GET
        else:
            ok, reason = effective_status(r.status_code, "")
            if ok:
                return False, f"head:{reason}"
            # Non-405 error — still try GET in case HEAD is unreliable
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        return True, f"head:ERR({e.__class__.__name__})"
    except Exception:
        pass

    # GET fallback — read only first 8 KB for CDN block detection
    try:
        r = requests.get(url, headers=headers, timeout=LINK_CHECK_TIMEOUT,
                         allow_redirects=True, verify=False, stream=True)
        html_snippet = b""
        for chunk in r.iter_content(chunk_size=8192):
            html_snippet = chunk
            break
        ok, reason = effective_status(r.status_code, html_snippet.decode("utf-8", errors="ignore"))
        return not ok, f"get:{reason}"
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        return True, f"get:ERR({e.__class__.__name__})"
    except Exception as e:
        return True, f"get:ERR({e.__class__.__name__})"


def check_links_parallel(links: list, link_cache: dict, cache_lock: threading.Lock,
                          result_q: queue.Queue) -> list:
    """Check links in parallel; use shared cache to skip already-checked URLs."""
    results  = []
    to_check = []

    for url in links:
        with cache_lock:
            if url in link_cache:
                results.append({"url": url, **link_cache[url]})
                result_q.put({"type": "link_progress"})
                continue
        to_check.append(url)

    if not to_check:
        return results

    futures = {}
    with ThreadPoolExecutor(max_workers=LINK_CHECK_WORKERS) as pool:
        for url in to_check:
            futures[pool.submit(check_link_fast, url)] = url

        for future in as_completed(futures):
            url = futures[future]
            try:
                broken, detail = future.result()
            except Exception as e:
                broken, detail = True, f"ERR({e.__class__.__name__})"

            entry = {"broken": broken, "detail": detail}
            with cache_lock:
                link_cache[url] = entry

            results.append({"url": url, **entry})
            result_q.put({"type": "link_progress"})

    return results


# ========================= PAGE FETCH WITH FALLBACK =========================
def fetch_page_with_fallback(page_url: str, ctx=None):
    base_url = normalize_url(page_url)

    # Strategy A: requests
    log.info(f"[fetch] requests -> {base_url}")
    try:
        session = requests.Session()
        headers = get_headers()
        session.head(base_url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        time.sleep(random.uniform(0.3, 0.8))
        resp = session.get(base_url, headers=headers, timeout=20, verify=False, allow_redirects=True)
        html = resp.text
        ok, reason = effective_status(resp.status_code, html)
        if ok:
            return html, "requests", False
        log.warning(f"[fetch] requests not usable: {reason}")
    except Exception as e:
        log.warning(f"[fetch] requests exception: {e}")

    # Strategy B: curl
    log.info(f"[fetch] curl -> {base_url}")
    try:
        ua     = random_ua()
        result = subprocess.run([
            "curl", "-s", "-L", "-k", "--max-time", "30",
            "-A", ua,
            "-H", "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.9",
            "-H", "Accept-Encoding: gzip, deflate",
            "-H", "Connection: keep-alive",
            "--compressed", "-w", "\n__STATUS__%{http_code}", base_url
        ], capture_output=True, text=True, timeout=35)
        output       = result.stdout
        status_match = re.search(r"__STATUS__(\d+)$", output)
        status_code  = int(status_match.group(1)) if status_match else 0
        html         = re.sub(r"\n__STATUS__\d+$", "", output)
        ok, reason   = effective_status(status_code, html)
        if ok:
            return html, "curl", False
        log.warning(f"[fetch] curl not usable: {reason}")
    except Exception as e:
        log.warning(f"[fetch] curl exception: {e}")

    # Strategy C: Playwright stealth
    if ctx is not None:
        log.info(f"[fetch] Playwright -> {base_url}")
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
            r           = page.goto(base_url, wait_until="networkidle", timeout=45000)
            page.wait_for_selector("body", timeout=10000)
            page.evaluate("() => { window.scrollTo(0, document.body.scrollHeight / 2); }")
            page.wait_for_timeout(800)
            page.evaluate("() => { window.scrollTo(0, document.body.scrollHeight); }")
            page.wait_for_timeout(800)
            page.evaluate("() => { window.scrollTo(0, 0); }")
            page.wait_for_timeout(1000)
            status_code = r.status if r else 0
            html        = page.content()
            page.close()
            ok, reason  = effective_status(status_code, html)
            if ok:
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


# ========================= PLAYWRIGHT SETUP =========================
def make_browser_context(p):
    browser = p.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-blink-features=AutomationControlled", "--disable-infobars"]
    )
    ctx = browser.new_context(
        ignore_https_errors=True,
        user_agent=random_ua(),
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


# ========================= BFS CRAWLER + SCAN ENGINE =========================
def crawl_and_scan(
    scan_id:   str,
    seed_urls: list,
    run_spell: bool,
    run_links: bool,
    do_crawl:  bool,
    max_pages: int,
    max_depth: int,
):
    """
    BFS crawler / scan engine.
    - do_crawl=False: scans only the provided seed_urls (original behaviour).
    - do_crawl=True:  starts from seeds, discovers same-domain links, crawls up to
                      max_pages pages at max_depth BFS depth.
    - Link checking is always done with the fast parallel checker + shared cache.
    """
    state = scans[scan_id]

    # Shared link-check cache for this scan
    link_cache:      dict             = {}
    cache_lock:      threading.Lock   = threading.Lock()

    # Rate limiter: domain -> last request time
    domain_last:     dict             = {}
    domain_lock:     threading.Lock   = threading.Lock()

    # BFS state
    bfs_q:           queue.Queue      = queue.Queue()
    visited:         set              = set()
    visited_lock:    threading.Lock   = threading.Lock()
    pages_queued     = 0

    result_q: queue.Queue = queue.Queue()

    def rate_limit(url: str):
        domain = get_domain(url)
        with domain_lock:
            last = domain_last.get(domain, 0)
            wait = CRAWL_RATE_DELAY - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            domain_last[domain] = time.time()

    # Seed the BFS queue
    allowed_domains = set()
    for raw_url in seed_urls:
        u = normalize_url(raw_url)
        allowed_domains.add(get_domain(u))
        with visited_lock:
            if u not in visited:
                visited.add(u)
                bfs_q.put((u, 0))
                pages_queued += 1

    state["total_pages"] = pages_queued

    # ── drain thread ─────────────────────────────────────────────────────────
    def drain():
        while True:
            msg = result_q.get()

            if msg["type"] == "page_done":
                state["pages_done"] += 1
                state["results"].append({
                    "page_url":       msg["page_url"],
                    "typos":          msg["typos"],
                    "links":          msg["links"],
                    "fetch_strategy": msg.get("fetch_strategy", "unknown"),
                    "depth":          msg.get("depth", 0),
                })
                bc = sum(1 for l in msg["links"] if l.get("broken"))
                line = (
                    f"[d{msg.get('depth',0)}] {msg['page_url']} | "
                    f"{msg.get('fetch_strategy','?')} | "
                    f"links={len(msg['links'])} ({bc} broken) | "
                    f"typos={len(msg['typos'])}"
                )
                state["log"] = (state["log"] + [line])[-15:]

            elif msg["type"] == "link_progress":
                state["total_links_checked"] += 1

            elif msg["type"] == "page_discovered":
                # Crawler found a new page — enqueue if within limits
                nonlocal pages_queued
                url   = msg["url"]
                depth = msg["depth"]
                with visited_lock:
                    if url not in visited and pages_queued < max_pages:
                        visited.add(url)
                        pages_queued += 1
                        state["total_pages"] = pages_queued
                        bfs_q.put((url, depth))

            elif msg["type"] == "page_error":
                state["pages_done"] += 1
                state["results"].append({
                    "page_url":       msg["page_url"],
                    "typos":          [],
                    "links":          [],
                    "error":          msg["msg"],
                    "fetch_strategy": "failed",
                    "depth":          msg.get("depth", 0),
                })
                line = f"ERR {msg['page_url']} — {msg['msg']}"
                state["log"] = (state["log"] + [line])[-15:]
                log.error(f"[drain] {line}")

            elif msg["type"] == "done":
                state["status"] = "done"
                break

            result_q.task_done()

    drain_thread = threading.Thread(target=drain, daemon=True)
    drain_thread.start()

    # ── main crawl loop (single Playwright browser for the whole scan) ────────
    with sync_playwright() as p:
        browser, ctx = make_browser_context(p)
        try:
            while True:
                try:
                    page_url, depth = bfs_q.get(timeout=5)
                except queue.Empty:
                    break  # no more pages

                try:
                    rate_limit(page_url)
                    log.info(f"[crawler] d={depth} {page_url}")

                    html, strategy, blocked = fetch_page_with_fallback(page_url, ctx)

                    if blocked or not html:
                        result_q.put({
                            "type": "page_error", "page_url": page_url,
                            "depth": depth,
                            "msg": f"Bot protection / access denied (tried: {strategy})",
                        })
                        bfs_q.task_done()
                        continue

                    all_links = extract_links_from_html(html, page_url) if run_links else []

                    # Discover same-domain links for BFS
                    if do_crawl and depth < max_depth:
                        for link_url in all_links:
                            if get_domain(link_url) in allowed_domains:
                                result_q.put({
                                    "type": "page_discovered",
                                    "url":   link_url,
                                    "depth": depth + 1,
                                })

                    typos = check_spelling_from_text(extract_text_from_html(html)) if run_spell else []

                    link_results = check_links_parallel(
                        all_links, link_cache, cache_lock, result_q
                    )

                    result_q.put({
                        "type":           "page_done",
                        "page_url":       page_url,
                        "depth":          depth,
                        "typos":          typos,
                        "links":          link_results,
                        "fetch_strategy": strategy,
                    })

                except Exception as ex:
                    log.error(f"[crawler] Unexpected error on {page_url}: {ex}")
                    result_q.put({
                        "type": "page_error", "page_url": page_url,
                        "depth": depth, "msg": str(ex),
                    })
                finally:
                    bfs_q.task_done()
        finally:
            browser.close()

    result_q.put({"type": "done"})
    drain_thread.join()
    log.info(f"[scan] {scan_id} complete — {state['pages_done']} pages")


# ========================= SCAN STATE =========================
scans = {}


class ScanRequest(BaseModel):
    urls:        list
    run_spell:   bool = True
    run_links:   bool = True
    num_workers: int  = 1       # kept for API compat
    do_crawl:    bool = False
    max_pages:   int  = DEFAULT_MAX_PAGES
    max_depth:   int  = DEFAULT_MAX_DEPTH


@app.post("/api/scan/start")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "status":               "running",
        "results":              [],
        "pages_done":           0,
        "total_pages":          len(req.urls),
        "total_links_checked":  0,
        "log":                  [],
    }
    background_tasks.add_task(
        crawl_and_scan,
        scan_id, req.urls, req.run_spell, req.run_links,
        req.do_crawl, req.max_pages, req.max_depth,
    )
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in scans:
        return {"error": "Scan not found"}
    state     = scans[scan_id]
    all_links = [lnk for r in state.get("results", []) for lnk in r.get("links", [])]
    broken    = [lnk for lnk in all_links if lnk.get("broken")]
    return {
        "status":              state.get("status"),
        "pages_done":          state.get("pages_done", 0),
        "total_pages":         state.get("total_pages", 0),
        "total_links_checked": state.get("total_links_checked", 0),
        "log":                 state.get("log", []),
        "results":             state.get("results", []),
        "metrics": {
            "total_links": len(all_links),
            "broken":      len(broken),
            "ok_links":    len(all_links) - len(broken),
        },
    }


# ========================= EXPORT =========================
@app.get("/api/scan/{scan_id}/export")
def export_scan(scan_id: str, fmt: str = "json"):
    if scan_id not in scans:
        return {"error": "Scan not found"}
    state   = scans[scan_id]
    results = state.get("results", [])

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["page_url", "link_url", "broken", "detail", "depth"])
        for page in results:
            for lnk in page.get("links", []):
                writer.writerow([
                    page["page_url"], lnk.get("url", ""),
                    lnk.get("broken", False), lnk.get("detail", ""),
                    page.get("depth", 0),
                ])
        writer.writerow([])
        writer.writerow(["page_url", "word", "suggestion", "context"])
        for page in results:
            for t in page.get("typos", []):
                writer.writerow([
                    page["page_url"], t.get("word", ""),
                    t.get("suggestion", ""), t.get("context", ""),
                ])
        output.seek(0)
        return StreamingResponse(
            output, media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.csv"},
        )

    # JSON default
    payload = {
        "scan_id": scan_id,
        "status":  state.get("status"),
        "metrics": {
            "pages_scanned":       state.get("pages_done", 0),
            "total_links_checked": state.get("total_links_checked", 0),
        },
        "results": results,
    }
    output = io.StringIO(json.dumps(payload, indent=2))
    return StreamingResponse(
        output, media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.json"},
    )


# ========================= DICTIONARY =========================
USER_DICT_FILE = "user_dictionary.txt"

def load_user_dict() -> set:
    try:
        with open(USER_DICT_FILE, "r") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


@app.get("/api/dictionary")
def get_dictionary():
    return {"words": sorted(load_user_dict())}


class DictWord(BaseModel):
    word: str


@app.post("/api/dictionary/add")
def add_word(req: DictWord):
    word = req.word.strip().lower()
    if not word:
        return {"ok": False, "error": "empty word"}
    words = load_user_dict()
    words.add(word)
    with open(USER_DICT_FILE, "w") as f:
        for w in sorted(words):
            f.write(w + "\n")
    return {"ok": True, "word": word}


@app.post("/api/dictionary/remove")
def remove_word(req: DictWord):
    word = req.word.strip().lower()
    words = load_user_dict()
    words.discard(word)
    with open(USER_DICT_FILE, "w") as f:
        for w in sorted(words):
            f.write(w + "\n")
    return {"ok": True, "word": word}


# ========================= CAPABILITIES =========================
@app.get("/api/capabilities")
def capabilities():
    return {
        "spellcheck":          True,
        "spellcheck_engine":   f"ollama/{OLLAMA_MODEL}",
        "spellcheck_fallback": SPELLCHECK_FALLBACK_AVAILABLE,
        "spacy":               SPACY_AVAILABLE,
        "stealth":             True,
        "crawler":             True,
        "fast_link_check":     True,
    }


@app.get("/")
def serve_index():
    return FileResponse("static/index1.html")