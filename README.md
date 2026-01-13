# Daily Mirror breaking news 4f0 Telegram bot

This bot scrapes the breaking news list at:

- https://www.dailymirror.lk/breaking_news/108

It extracts all breaking-news article links from that page, downloads each article,
extracts the main content, and sends it to a Telegram chat via a bot.

The logic is aligned with the existing Newsfirst bot:

- Uses `requests` + `BeautifulSoup` to parse the raw HTML (no API endpoints).
- Tracks already-sent articles in a local JSON file `sent_articles.json`.
- Detects duplicates using both the article URL and a SHA-256 hash of the
  extracted content.
- Cleans up tracking data older than 7 days.

## Running locally

1. Create / activate a Python 3.11+ environment.
2. Install dependencies from this folder:

   ```bash
   pip install -r requirements.txt
   ```

3. Export your Telegram bot token and chat ID (same names as the other bot):

   ```bash
   # PowerShell
   $env:TELEGRAM_BOT_TOKEN="YOUR_TOKEN_HERE"
   $env:TELEGRAM_CHAT_ID="YOUR_CHAT_ID_HERE"
   ```

4. From this folder, run the scraper:

   ```bash
   python dm_news_scraper.py
   ```

On the first run it will likely send all currently listed breaking news
articles; subsequent runs will skip anything already sent using the
`sent_articles.json` tracking file in this directory.

## Notes

- The scraper uses a desktop browser User-Agent to improve compatibility
  with the Daily Mirror site.
- Content extraction is heuristic: it looks for common article containers
  and falls back to filtering `<p>` tags by length, so it should be
  reasonably robust to minor layout changes.
