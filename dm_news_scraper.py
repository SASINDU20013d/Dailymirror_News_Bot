import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


BASE_URL = "https://www.dailymirror.lk"
BREAKING_NEWS_PATH = "/breaking_news/108"
BREAKING_NEWS_URL = f"{BASE_URL}{BREAKING_NEWS_PATH}"
# Keep tracking JSON next to this script so it doesn't clash
# with other bots when run from the repo root.
SENT_ARTICLES_PATH = Path(__file__).with_name("sent_articles.json")
RETENTION_DAYS = 7


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime (Python 3.12+ compatible)."""
    return datetime.now(timezone.utc)


def _create_session() -> requests.Session:
    """
    Create a requests Session with retry logic and browser-like headers.
    
    Retries help with transient network issues. Browser headers reduce
    likelihood of being blocked (403) by the remote site.
    """
    session = requests.Session()
    
    # Configure retries for transient errors (network issues, 5xx server errors)
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set browser-like headers to reduce likelihood of 403s
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    
    return session


# Global session instance for reuse across requests
_SESSION = _create_session()


def fetch_url_text(url: str, timeout: int = 15) -> str | None:
    """
    Fetch URL text using the session with retries and error handling.
    
    Treats 403 Forbidden as non-fatal (logs and returns None) to avoid
    failing the entire job when the remote site blocks requests.
    
    Returns None on any request failure to keep the script resilient.
    """
    try:
        resp = _SESSION.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 403:
            # 403 Forbidden is non-fatal; remote site may be blocking us temporarily
            print(
                f"⚠️  Received 403 Forbidden from {url}. Remote site may be blocking requests.",
                file=sys.stderr,
            )
            return None
        # Other HTTP errors are also non-fatal; log and return None
        print(f"❌ HTTP error fetching {url}: {exc}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as exc:
        # Network errors, timeouts, etc. are non-fatal
        print(f"❌ Request error fetching {url}: {exc}", file=sys.stderr)
        return None


def fetch_html(url: str) -> str:
    """Legacy wrapper that raises on failure (kept for compatibility)."""
    text = fetch_url_text(url, timeout=20)
    if text is None:
        raise RuntimeError(f"Failed to fetch {url}")
    return text


def extract_article_content(article_url: str) -> Tuple[str, str]:
    """Fetch a single article page and extract title + body text."""

    html = fetch_html(article_url)
    soup = BeautifulSoup(html, "html.parser")

    # Title
    title_tag = soup.find("h1") or soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else article_url

    # Try common article content containers first
    article_node = (
        soup.find("div", class_="news-content")
        or soup.find("div", class_="article-content")
        or soup.find("article")
        or soup.find("div", class_="post-content")
        or soup.body
        or soup
    )

    paragraphs: List[str] = []
    for p in article_node.find_all("p"):
        text = p.get_text(" ", strip=True)
        if not text:
            continue
        # Skip very short / boilerplate lines
        if len(text) < 30:
            continue
        paragraphs.append(text)

    if not paragraphs:
        paragraphs.append("Content not clearly detected from page.")

    body = "\n\n".join(paragraphs[:4])  # limit paragraphs

    # Telegram hard limit is 4096; stay safely below
    max_len = 3500
    if len(body) > max_len:
        body = body[:max_len].rstrip() + "..."

    return title, body


def build_message(title: str, body: str, url: str) -> str:
    return f"{title}\n\n{body}\n\nRead more: {url}"


def generate_content_hash(title: str, body: str) -> str:
    """Generate a stable SHA-256 hash for an article's content."""

    normalized = (title or "").strip() + "\n\n" + (body or "").strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _empty_store() -> Dict[str, List[Dict[str, Any]]]:
    return {"articles": []}


def load_sent_articles(path: Path = SENT_ARTICLES_PATH) -> Dict[str, List[Dict[str, Any]]]:
    """Load tracking data from JSON file, returning an empty structure on errors."""

    if not path.exists():
        return _empty_store()

    try:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return _empty_store()
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"❌ Failed to load {path.name}: {exc}. Starting with an empty store.", file=sys.stderr)
        return _empty_store()

    if isinstance(data, dict) and "articles" in data and isinstance(data["articles"], list):
        return data  # type: ignore[return-value]

    print(f"❌ Unexpected format in {path.name}. Resetting tracking store.", file=sys.stderr)
    return _empty_store()


def cleanup_old_articles(
    store: Dict[str, List[Dict[str, Any]]],
    retention_days: int = RETENTION_DAYS,
) -> Dict[str, List[Dict[str, Any]]]:
    """Remove articles older than the retention period."""

    cutoff = utc_now() - timedelta(days=retention_days)
    cleaned: List[Dict[str, Any]] = []

    for article in store.get("articles", []):
        sent_at_str = article.get("sent_at")
        if not isinstance(sent_at_str, str):
            cleaned.append(article)
            continue
        try:
            ts = sent_at_str.rstrip("Z")
            sent_at = datetime.fromisoformat(ts)
            # Make timezone-aware if not already
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=timezone.utc)
        except ValueError:
            print(
                f"❌ Invalid sent_at timestamp '{sent_at_str}' in tracking store; keeping entry but it won't be pruned.",
                file=sys.stderr,
            )
            cleaned.append(article)
            continue

        if sent_at >= cutoff:
            cleaned.append(article)

    pruned_count = len(store.get("articles", [])) - len(cleaned)
    if pruned_count > 0:
        print(f"🧹 Cleaned up {pruned_count} old tracked article(s) older than {retention_days} days.")

    return {"articles": cleaned}


def is_article_sent(
    url: str,
    content_hash: str,
    store: Dict[str, List[Dict[str, Any]]],
) -> Tuple[bool, str | None]:
    """Check if an article was already sent, by URL or content hash."""

    for article in store.get("articles", []):
        stored_url = article.get("url")
        stored_hash = article.get("content_hash")
        sent_at = article.get("sent_at")

        if stored_url == url:
            reason = (
                f"URL already sent on {sent_at}" if sent_at else "URL already sent previously"
            )
            return True, reason
        if stored_hash == content_hash:
            reason = (
                f"Content already sent on {sent_at}" if sent_at else "Content already sent previously"
            )
            return True, reason

    return False, None


def save_sent_article(
    url: str,
    content_hash: str,
    title: str,
    store: Dict[str, List[Dict[str, Any]]],
) -> None:
    """Append a newly sent article to the in-memory store."""

    # Remove timezone info before isoformat to match old format (naive datetime + Z)
    now = utc_now().replace(microsecond=0, tzinfo=None).isoformat() + "Z"
    store.setdefault("articles", []).append(
        {
            "url": url,
            "content_hash": content_hash,
            "title": title,
            "sent_at": now,
        }
    )


def save_sent_articles_to_file(
    store: Dict[str, List[Dict[str, Any]]],
    path: Path = SENT_ARTICLES_PATH,
) -> None:
    """Persist tracking data to disk as pretty-printed JSON."""

    try:
        path.write_text(json.dumps(store, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"❌ Failed to write {path.name}: {exc}", file=sys.stderr)


def send_telegram_message(token: str, chat_id: str, text: str) -> None:
    api_url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }
    resp = requests.post(api_url, json=payload, timeout=20)
    try:
        resp.raise_for_status()
    except requests.HTTPError as exc:
        print(f"❌ Failed to send message: {exc} - response: {resp.text[:500]}", file=sys.stderr)


def main(argv: List[str]) -> None:
    if len(argv) != 1:
        raise SystemExit("Usage: python dm_news_scraper.py")

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not bot_token or not chat_id:
        raise SystemExit("Environment variables TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set.")

    # Load and clean existing tracking data
    sent_store = load_sent_articles()
    sent_store = cleanup_old_articles(sent_store, RETENTION_DAYS)
    tracked_count = len(sent_store.get("articles", []))

    print(f"📊 Currently tracking {tracked_count} articles from last {RETENTION_DAYS} days")
    print(f"🔍 Fetching breaking news list: {BREAKING_NEWS_URL}")

    # Fetch breaking news list with non-fatal error handling
    # If fetch fails (e.g., 403 or network error), exit gracefully with code 0
    # so the GitHub Actions job doesn't fail for upstream issues.
    html = fetch_url_text(BREAKING_NEWS_URL, timeout=20)
    if html is None:
        print(
            "⚠️  Could not fetch breaking news list (likely upstream 403 or network error).",
            file=sys.stderr,
        )
        print("Exiting with success (code 0) to avoid failing the Actions job for upstream issues.")
        sys.exit(0)

    try:
        # Parse the HTML to extract article links
        soup = BeautifulSoup(html, "html.parser")
        links: set[str] = set()
        prefix = f"{BASE_URL}/breaking-news/"

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            full_url = urljoin(BREAKING_NEWS_URL, href)

            if not full_url.startswith(prefix):
                continue
            # Skip print or other non-standard variants
            if "/print/" in full_url:
                continue

            links.add(full_url)

        article_links = sorted(links)
    except Exception as exc:  # noqa: BLE001
        print(f"❌ Error parsing breaking news list: {exc}", file=sys.stderr)
        print("Exiting with success (code 0) to avoid failing the Actions job.")
        sys.exit(0)

    if not article_links:
        print("No breaking news articles found on page.")
        return

    total = len(article_links)
    print(f"📰 Found {total} breaking news articles on page")

    sent_count = 0
    skipped_count = 0
    error_count = 0

    for idx, article_url in enumerate(article_links, start=1):
        try:
            title, body = extract_article_content(article_url)
            content_hash = generate_content_hash(title, body)

            is_sent, reason = is_article_sent(article_url, content_hash, sent_store)
            if is_sent:
                skipped_count += 1
                extra = f" ({reason})" if reason else ""
                print(f"⏭ [{idx}/{total}] SKIP: {title}{extra}")
                continue

            message = build_message(title, body, article_url)
            send_telegram_message(bot_token, chat_id, message)

            save_sent_article(article_url, content_hash, title, sent_store)
            save_sent_articles_to_file(sent_store)

            sent_count += 1
            print(f"✅ [{idx}/{total}] SENT: {title}")
        except Exception as exc:  # noqa: BLE001
            error_count += 1
            print(f"❌ [{idx}/{total}] ERROR processing {article_url}: {exc}", file=sys.stderr)

    # Final save (in case cleanup pruned anything earlier in the run)
    sent_store = cleanup_old_articles(sent_store, RETENTION_DAYS)
    save_sent_articles_to_file(sent_store)

    print(f"📤 Sent: {sent_count} | ⏭ Skipped: {skipped_count} | ❌ Errors: {error_count}")


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv)
