import re
import queue
import threading
import subprocess
import collections
import uuid
from datetime import datetime

import requests
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth
from urllib.parse import urljoin, urlparse

# ── exact deps from pasted code ───────────────────────────────────────────────
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

# ── exact constants from pasted code ─────────────────────────────────────────
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xhtml+xml,*/*;q=0.8",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
}

BASE_IGNORE = {
    "url", "html", "css", "js", "pdf", "http", "https", "www",
    "id", "ids", "api", "ui", "ux", "ok", "faq"
}

CONFIDENCE_THRESHOLD = 0.4

# ── exact functions from pasted code (not a single difference) ────────────────

def extract_text(page):
    """Pull all visible text from the page, skipping script/style/code tags."""
    return page.evaluate("""() => {
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            {
                acceptNode(node) {
                    const tag = node.parentElement?.tagName?.toLowerCase();
                    if (['script','style','noscript','code','pre'].includes(tag)) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return node.textContent.trim()
                        ? NodeFilter.FILTER_ACCEPT
                        : NodeFilter.FILTER_SKIP;
                }
            }
        );
        const texts = [];
        let node;
        while ((node = walker.nextNode())) {
            texts.push(node.textContent.trim());
        }
        return texts.join(' ');
    }""")


def build_dynamic_ignore(raw_text, word_freq):
    """
    Dynamically build an ignore set without any manual lists.

    Strategy 1 — NER via spaCy:
        Automatically detect proper nouns, person names, places,
        organisations, and products and add them to the ignore set.

    Strategy 2 — Frequency filter:
        Any word that appears 3+ times on the page is almost certainly
        intentional (brand name, domain term, repeated label). Ignore it.

    Strategy 3 — All-caps / title-case acronyms:
        Words that appear only in ALL CAPS or TitleCase are likely
        acronyms, abbreviations, or proper nouns.
    """
    dynamic_ignore = set(BASE_IGNORE)

    # Strategy 1: spaCy NER — skip if unavailable
    if SPACY_AVAILABLE:
        # spaCy has a 1M char limit; truncate if needed
        doc = nlp(raw_text[:1_000_000])
        for ent in doc.ents:
            # PERSON, ORG, GPE (geo), LOC, PRODUCT, EVENT, WORK_OF_ART, LAW, LANGUAGE
            for token in ent:
                dynamic_ignore.add(token.text.lower())
        # Also skip any token spaCy tagged as a proper noun (PROPN)
        for token in doc:
            if token.pos_ == "PROPN":
                dynamic_ignore.add(token.text.lower())

    # Strategy 2: frequency filter — words appearing 3+ times
    for word, count in word_freq.items():
        if count >= 3:
            dynamic_ignore.add(word.lower())

    # Strategy 3: words that only appear in ALL CAPS form are acronyms
    all_words_raw = re.findall(r"\b[a-zA-Z]{2,}\b", raw_text)
    case_forms = collections.defaultdict(set)
    for w in all_words_raw:
        case_forms[w.lower()].add(w)
    for lower, forms in case_forms.items():
        if all(f.isupper() or f.istitle() for f in forms):
            dynamic_ignore.add(lower)

    return dynamic_ignore


def check_spelling(page):
    """
    Dynamically spell-check the page with zero hardcoded site-specific words.
    Returns list of dicts with word, suggestion, context.
    """
    if not SPELLCHECK_AVAILABLE:
        return []

    raw_text = extract_text(page)
    spell = SpellChecker()

    # All alphabetic words 3+ chars
    all_words = re.findall(r"\b[a-zA-Z]{3,}\b", raw_text)
    word_freq = collections.Counter(w.lower() for w in all_words)

    # Build dynamic ignore set
    ignore = build_dynamic_ignore(raw_text, word_freq)

    # Filter candidates: not ignored, not all-caps
    candidates = [
        w for w in all_words
        if w.lower() not in ignore and not w.isupper()
    ]

    misspelled = spell.unknown(candidates)

    results = []
    seen = set()
    for word in misspelled:
        if word in seen:
            continue
        seen.add(word)

        suggestion = spell.correction(word)
        if suggestion == word:
            continue  # checker isn't sure either — skip

        # Context snippet
        pattern = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
        match = pattern.search(raw_text)
        if match:
            start = max(0, match.start() - 40)
            end = min(len(raw_text), match.end() + 40)
            snippet = raw_text[start:end].replace("\n", " ").strip()
            ctx_snippet = f"...{snippet}..."
        else:
            ctx_snippet = "(no context)"

        results.append({"word": word, "suggestion": suggestion, "context": ctx_snippet})

    return sorted(results, key=lambda x: x["word"])


def get_visible_links(page, base_url):
    links = page.locator("a:visible")
    urls = set()

    count = links.count()
    for i in range(count):
        href = links.nth(i).get_attribute("href")
        if not href:
            continue
        full_url = urljoin(base_url, href)
        if urlparse(full_url).scheme in ("http", "https") and not full_url.lower().endswith(".pdf"):
            urls.add(full_url)

    return list(urls)


# Method 1: Stealth Playwright
def try_playwright(browser_context, url):
    page = browser_context.new_page()
    Stealth().apply_stealth_sync(page)
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
        status = response.status if response else 0
        page.close()
        if status < 400:
            return True, f"playwright:{status}"
        return False, f"playwright:{status}"
    except Exception:
        page.close()
        return False, "playwright:ERR"


# Method 2: requests
def try_requests(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True, verify=False)
        if response.status_code < 400:
            return True, f"requests:{response.status_code}"
        return False, f"requests:{response.status_code}"
    except Exception:
        return False, "requests:ERR"


# Method 3: curl
def try_curl(url):
    try:
        result = subprocess.run(
            [
                "curl", "-o", "/dev/null", "-s",
                "-w", "%{http_code}",
                "-L", "-k",
                "--max-time", "20",
                "-H", f"User-Agent: {HEADERS['User-Agent']}",
                "-H", f"Accept-Language: {HEADERS['Accept-Language']}",
                "-H", f"Accept: {HEADERS['Accept']}",
                url,
            ],
            capture_output=True, text=True, timeout=15,
        )
        status = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
        if status > 0 and status < 400:
            return True, f"curl:{status}"
        return False, f"curl:{status or 'ERR'}"
    except Exception:
        return False, "curl:ERR"


def is_reachable(browser_context, url):
    ok, detail = try_playwright(browser_context, url)
    if ok:
        return False, detail
    ok, detail2 = try_requests(url)
    if ok:
        return False, detail2
    ok, detail3 = try_curl(url)
    if ok:
        return False, detail3
    return True, f"{detail} | {detail2} | {detail3}"


# ── FastAPI infrastructure ─────────────────────────────────────────────────────

USER_DICT_FILE = "user_dictionary.txt"
scans: dict = {}

app = FastAPI(title="Web Audit Tool")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_user_dict() -> set:
    try:
        with open(USER_DICT_FILE, "r") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def save_word_to_dict(word: str):
    with open(USER_DICT_FILE, "a") as f:
        f.write(word.lower().strip() + "\n")


def remove_word_from_dict(word: str):
    try:
        with open(USER_DICT_FILE, "r") as f:
            words = {line.strip().lower() for line in f if line.strip()}
        words.discard(word.lower())
        with open(USER_DICT_FILE, "w") as f:
            f.write("\n".join(sorted(words)) + ("\n" if words else ""))
    except FileNotFoundError:
        pass


def parse_sitemap_txt(content: str) -> list:
    urls = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parsed = urlparse(line)
            if parsed.scheme in ("http", "https"):
                urls.append(line)
    return urls


def make_browser_context(playwright):
    browser = playwright.chromium.launch(headless=True)
    ctx = browser.new_context(
        ignore_https_errors=True,
        user_agent=HEADERS["User-Agent"],
        extra_http_headers={
            "Accept-Language": HEADERS["Accept-Language"],
            "Accept": HEADERS["Accept"],
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        },
        viewport={"width": 1280, "height": 800},
        locale="en-US",
    )
    return browser, ctx


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
                    page = ctx.new_page()
                    Stealth().apply_stealth_sync(page)
                    page.goto(page_url, wait_until="domcontentloaded", timeout=20000)
                    page.wait_for_selector("body")

                    typos       = check_spelling(page) if run_spell else []
                    links_found = get_visible_links(page, page_url) if run_links else []
                    page.close()

                    result_q.put({"type": "status", "msg": f"Found {len(links_found)} link(s) on {page_url} — checking each…"})

                    link_results = []
                    for link in links_found:
                        broken, detail = is_reachable(ctx, link)
                        link_results.append({"url": link, "broken": broken, "detail": detail})
                        result_q.put({"type": "link_progress"})

                    result_q.put({
                        "type":        "page_done",
                        "page_url":    page_url,
                        "typos":       typos,
                        "links":       link_results,
                        "links_found": len(links_found),
                    })

                except Exception as ex:
                    result_q.put({
                        "type":     "page_error",
                        "page_url": page_url,
                        "msg":      str(ex),
                    })
                finally:
                    work_q.task_done()
        finally:
            browser.close()


def drain_queue(result_q, scan_id):
    state = scans[scan_id]
    while True:
        try:
            msg = result_q.get(timeout=3)
        except queue.Empty:
            if state["status"] in ("done", "error"):
                break
            continue

        t = msg["type"]

        if t == "status":
            state["status_msg"] = msg["msg"]
            state["log"].append(msg["msg"])

        elif t == "total_pages":
            state["total_pages"] = msg["total"]

        elif t == "link_progress":
            state["total_links_checked"] += 1

        elif t == "page_done":
            state["pages_done"] += 1
            state["results"].append({
                "page_url": msg["page_url"],
                "typos":    msg["typos"],
                "links":    msg["links"],
            })
            n_links  = msg.get("links_found", len(msg["links"]))
            n_broken = sum(1 for l in msg["links"] if l["broken"])
            n_typos  = len(msg["typos"])
            state["log"].append(
                f"✓ {msg['page_url']} — {n_links} link(s) found, "
                f"{n_broken} broken, {n_typos} typo(s)"
            )

        elif t == "page_error":
            state["pages_done"] += 1
            state["results"].append({
                "page_url": msg["page_url"],
                "error":    msg["msg"],
                "typos":    [],
                "links":    [],
            })
            state["log"].append(f"✗ Error: {msg['page_url']} — {msg['msg']}")

        elif t == "done":
            state["status"] = "done"
            state["log"].append("✅ Scan complete.")
            result_q.task_done()
            break

        elif t == "error":
            state["status"] = "error"
            state["error"]  = msg["msg"]
            state["log"].append(f"❌ {msg['msg']}")
            result_q.task_done()
            break

        result_q.task_done()


def run_scan(scan_id, urls_to_audit, run_spell, run_links, num_workers):
    requests.packages.urllib3.disable_warnings()

    state = scans[scan_id]
    state["status"] = "running"

    result_q = queue.Queue()

    drain_thread = threading.Thread(
        target=drain_queue,
        args=(result_q, scan_id),
        daemon=True,
        name=f"drain-{scan_id[:8]}",
    )
    drain_thread.start()

    total_pages = len(urls_to_audit)
    result_q.put({"type": "total_pages", "total": total_pages})
    result_q.put({"type": "status", "msg": f"Starting {num_workers} worker(s) for {total_pages} page(s)…"})

    work_q = queue.Queue()
    for url in urls_to_audit:
        work_q.put(url)

    threads = []
    for i in range(min(num_workers, total_pages)):
        t = threading.Thread(
            target=worker,
            args=(work_q, result_q, run_spell, run_links),
            daemon=True,
            name=f"worker-{i+1}",
        )
        t.start()
        threads.append(t)
        result_q.put({"type": "status", "msg": f"Worker {i+1}/{num_workers} started…"})

    for t in threads:
        t.join()

    result_q.put({"type": "done"})
    drain_thread.join(timeout=15)


# ── API models ─────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    urls: list
    run_spell: bool = True
    run_links: bool = True
    num_workers: int = 3


class WordRequest(BaseModel):
    word: str


# ── API routes ─────────────────────────────────────────────────────────────────

@app.post("/api/scan/start")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "status":               "starting",
        "status_msg":           "Initialising…",
        "total_pages":          0,
        "pages_done":           0,
        "total_links_checked":  0,
        "results":              [],
        "log":                  [],
        "error":                None,
        "started_at":           datetime.utcnow().isoformat(),
    }
    background_tasks.add_task(
        run_scan, scan_id, req.urls, req.run_spell, req.run_links, req.num_workers
    )
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in scans:
        return {"error": "Scan not found"}

    state = scans[scan_id]
    user_dict = load_user_dict()

    all_links     = [l for r in state["results"] for l in r.get("links", [])]
    all_typos     = [t for r in state["results"] for t in r.get("typos", [])]
    broken        = [l for l in all_links if l["broken"]]
    visible_typos = [t for t in all_typos if t["word"].lower() not in user_dict]

    return {
        "status":               state["status"],
        "status_msg":           state.get("status_msg", ""),
        "total_pages":          state["total_pages"],
        "pages_done":           state["pages_done"],
        "total_links_checked":  state["total_links_checked"],
        "results":              state["results"],
        "log":                  state["log"][-15:],
        "error":                state.get("error"),
        "metrics": {
            "pages":       state["pages_done"],
            "total_links": len(all_links),
            "broken":      len(broken),
            "ok_links":    len(all_links) - len(broken),
            "typos":       len(visible_typos),
        },
    }


@app.get("/api/dictionary")
def get_dictionary():
    return {"words": sorted(load_user_dict())}


@app.post("/api/dictionary/add")
def add_word(req: WordRequest):
    save_word_to_dict(req.word)
    return {"ok": True}


@app.post("/api/dictionary/remove")
def remove_word(req: WordRequest):
    remove_word_from_dict(req.word)
    return {"ok": True}


@app.get("/api/capabilities")
def capabilities():
    return {
        "spellcheck": SPELLCHECK_AVAILABLE,
        "spacy":      SPACY_AVAILABLE,
        "stealth":    True,
    }


@app.get("/")
def serve_index():
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")