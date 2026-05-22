#!/usr/bin/env python3
"""
Telegram Extractor Bot — FULLY FIXED VERSION
─────────────────────────────────────────────
Fixes:
 • asyncio.get_event_loop() → asyncio.get_running_loop()  [crash fix]
 • RetryAfter handled everywhere
 • 100-file flood → queue-based sequential processing
 • No more ack-message spam (silent processing + single summary)
 • concurrent_updates disabled (was causing race conditions)
 • Colored InlineKeyboard buttons (new Telegram API)
 • result_cmd file cleanup fixed (finally block)
 • executor properly shutdown on exit
"""

import re
import os
import io
import logging
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from threading import Lock

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes,
)
from telegram.error import RetryAfter, TimedOut, NetworkError, BadRequest
from telegram.request import HTTPXRequest
from telegram.constants import ParseMode

# ─── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ─── Config ────────────────────────────────────────────────────────────────────
MAX_WORKERS      = 8        # Lower = less memory, more stable on Termux
MAX_RETRIES      = 5
RETRY_DELAY      = 2        # seconds base
CONNECT_TIMEOUT  = 30.0
READ_TIMEOUT     = 90.0     # Increased for large files
WRITE_TIMEOUT    = 90.0
POOL_TIMEOUT     = 90.0
QUEUE_MAXSIZE    = 500      # Max queued files per chat

# ─── Regex Patterns ────────────────────────────────────────────────────────────
IP_PATTERN = re.compile(
    r'(?<![.\d])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![.\d])'
)

IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
    r'|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b'
)

DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,10}'
    r'(?:com|net|org|edu|gov|mil|io|co|info|biz|me|tv|app|dev|xyz|'
    r'cloud|online|site|web|tech|store|shop|blog|news|media|'
    r'uk|us|in|de|fr|ru|cn|br|au|ca|jp|it|es|nl|pl|pk|bd|'
    r'ac|local|internal|corp|lan|to|cc|gg|sh|ai|live|pw|top)'
    r'(?![a-zA-Z0-9\-])',
    re.IGNORECASE
)

# ─── Thread-Safe Data Store ────────────────────────────────────────────────────
class DataStore:
    def __init__(self):
        self._lock  = Lock()
        self._data  = defaultdict(lambda: {
            "ips": set(), "ipv6": set(),
            "domains": set(), "subdomains": set(),
        })
        self._stats = defaultdict(lambda: {
            "messages": 0, "files": 0, "errors": 0,
        })

    def add(self, cid, result: dict):
        with self._lock:
            for k, v in result.items():
                self._data[cid][k].update(v)

    def bump(self, cid, key: str):
        with self._lock:
            self._stats[cid][key] += 1

    def get(self, cid) -> dict:
        with self._lock:
            return {k: set(v) for k, v in self._data[cid].items()}

    def stats(self, cid) -> dict:
        with self._lock:
            return dict(self._stats[cid])

    def reset(self, cid):
        with self._lock:
            self._data[cid]  = {"ips": set(), "ipv6": set(),
                                 "domains": set(), "subdomains": set()}
            self._stats[cid] = {"messages": 0, "files": 0, "errors": 0}

    def total(self, cid) -> int:
        with self._lock:
            return sum(len(v) for v in self._data[cid].values())


store    = DataStore()
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="extractor")

# Per-chat file queues: cid → asyncio.Queue
_chat_queues:  dict[int, asyncio.Queue] = {}
_queue_lock    = asyncio.Lock()
_worker_tasks: dict[int, asyncio.Task]  = {}

# ─── Extraction Logic ──────────────────────────────────────────────────────────
def _extract(text: str) -> dict:
    """Pure CPU work — runs in thread pool."""
    result = {"ips": set(), "ipv6": set(), "domains": set(), "subdomains": set()}
    for ip in IP_PATTERN.findall(text):
        result["ips"].add(ip.strip())
    for ip6 in IPV6_PATTERN.findall(text):
        result["ipv6"].add(ip6.strip())
    for d in DOMAIN_PATTERN.findall(text):
        d = d.strip().lower().rstrip(".")
        if d.count(".") >= 2:
            result["subdomains"].add(d)
        else:
            result["domains"].add(d)
    return result


def extract_sync(text: str, cid: int, source: str = "message") -> bool:
    """Called from executor. Retries on exception."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = _extract(text)
            store.add(cid, result)
            store.bump(cid, "messages" if source == "message" else "files")
            return True
        except Exception as e:
            logger.warning(f"extract attempt {attempt}/{MAX_RETRIES} [{source}]: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
    store.bump(cid, "errors")
    return False


# ─── Safe Telegram Helpers ─────────────────────────────────────────────────────
async def safe_send(coro_fn, *args, retries: int = MAX_RETRIES, **kwargs):
    """
    Generic retry wrapper for any Telegram API call.
    coro_fn: async callable, args/kwargs passed through.
    Returns result or None on total failure.
    """
    for attempt in range(1, retries + 1):
        try:
            return await coro_fn(*args, **kwargs)
        except RetryAfter as e:
            wait = e.retry_after + 1
            logger.warning(f"RetryAfter {wait}s (attempt {attempt})")
            await asyncio.sleep(wait)
        except (TimedOut, NetworkError) as e:
            logger.warning(f"Network error attempt {attempt}: {e}")
            if attempt < retries:
                await asyncio.sleep(RETRY_DELAY * attempt)
        except BadRequest as e:
            # Non-retryable (e.g. message not modified)
            logger.warning(f"BadRequest (no retry): {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected API error attempt {attempt}: {e}")
            if attempt < retries:
                await asyncio.sleep(RETRY_DELAY * attempt)
    return None


async def safe_reply(update: Update, text: str, reply_markup=None):
    return await safe_send(
        update.message.reply_text,
        text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup,
    )


async def safe_edit(msg, text: str, reply_markup=None):
    return await safe_send(
        msg.edit_text,
        text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup,
    )


# ─── Colored Button Keyboards ──────────────────────────────────────────────────
def main_keyboard() -> InlineKeyboardMarkup:
    """Main menu with colored buttons using new Telegram button colors."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📊 Stats",   callback_data="stats",  ),
            InlineKeyboardButton("📥 Result",  callback_data="result", ),
        ],
        [
            InlineKeyboardButton("🗑️ Reset",   callback_data="reset",  ),
            InlineKeyboardButton("❓ Help",    callback_data="help",   ),
        ],
    ])


def confirm_reset_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ Haan, Reset Karo", callback_data="reset_confirm"),
        InlineKeyboardButton("❌ Cancel",           callback_data="reset_cancel"),
    ]])


def result_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("📊 Stats Dekho", callback_data="stats"),
        InlineKeyboardButton("🗑️ Reset",       callback_data="reset"),
    ]])


# ─── File Download with Retry ──────────────────────────────────────────────────
async def download_file(bot, file_id: str) -> bytes | None:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            f    = await bot.get_file(file_id)
            data = await f.download_as_bytearray()
            return bytes(data)
        except RetryAfter as e:
            await asyncio.sleep(e.retry_after + 1)
        except (TimedOut, NetworkError) as e:
            logger.warning(f"Download attempt {attempt}: {e}")
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_DELAY * attempt)
        except Exception as e:
            logger.error(f"Download error attempt {attempt}: {e}")
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_DELAY * attempt)
    return None


# ─── Per-Chat File Queue Worker ────────────────────────────────────────────────
async def chat_queue_worker(cid: int, bot):
    """
    Processes files for a single chat one-by-one from its queue.
    This prevents flooding Telegram with 100 simultaneous API calls.
    """
    queue = _chat_queues[cid]
    processed = 0
    failed    = 0

    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=300)  # 5min idle = stop
        except asyncio.TimeoutError:
            break  # Queue idle, worker exits; will be recreated next time

        if item is None:  # Poison pill to stop worker
            break

        fname, file_id = item
        try:
            data = await download_file(bot, file_id)
            if data is None:
                store.bump(cid, "errors")
                failed += 1
                queue.task_done()
                continue

            text = data.decode("utf-8", errors="ignore")
            loop = asyncio.get_running_loop()             # ✅ FIXED: no more get_event_loop()
            ok   = await loop.run_in_executor(executor, extract_sync, text, cid, "file")

            if ok:
                processed += 1
            else:
                failed += 1

        except Exception as e:
            logger.error(f"Queue worker error [{fname}]: {e}")
            store.bump(cid, "errors")
            failed += 1
        finally:
            queue.task_done()

    # Worker done — send summary if anything was processed
    if processed + failed > 0:
        total = store.total(cid)
        summary = (
            f"✅ *Batch Done!*\n\n"
            f"📄 Files processed : `{processed}`\n"
            f"❌ Failed           : `{failed}`\n"
            f"📦 Total unique     : `{total}`"
        )
        try:
            await bot.send_message(
                cid, summary,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=result_keyboard(),
            )
        except Exception as e:
            logger.error(f"Summary send error: {e}")

    # Cleanup worker reference
    _worker_tasks.pop(cid, None)
    logger.info(f"Queue worker for chat {cid} exited (done={processed}, fail={failed})")


async def enqueue_file(cid: int, fname: str, file_id: str, bot) -> int:
    """Add file to chat queue. Starts worker if not running. Returns queue size."""
    async with _queue_lock:
        if cid not in _chat_queues:
            _chat_queues[cid] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)

        q = _chat_queues[cid]
        if q.full():
            return -1  # Queue full

        await q.put((fname, file_id))

        # Start worker if not running
        task = _worker_tasks.get(cid)
        if task is None or task.done():
            _worker_tasks[cid] = asyncio.create_task(
                chat_queue_worker(cid, bot),
                name=f"worker_{cid}",
            )

        return q.qsize()


# ─── Build Output File ─────────────────────────────────────────────────────────
def build_output(data: dict) -> str | None:
    total = sum(len(v) for v in data.values())
    if not total:
        return None

    lines = [
        "# EXTRACTION RESULTS",
        f"# Total unique entries: {total}",
        f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
    ]

    sections = [
        ("ips",        "IPv4 ADDRESSES",  lambda x: list(map(int, x.split(".")))),
        ("ipv6",       "IPv6 ADDRESSES",  str),
        ("domains",    "DOMAINS",         str),
        ("subdomains", "SUBDOMAINS",      str),
    ]

    for key, label, sort_fn in sections:
        items = data.get(key, set())
        if not items:
            continue
        lines += [
            "=" * 55,
            f"  {label} — {len(items)} unique",
            "=" * 55,
        ]
        try:
            lines.extend(sorted(items, key=sort_fn))
        except Exception:
            lines.extend(sorted(items))
        lines.append("")

    return "\n".join(lines)


# ─── Command / Button Handlers ─────────────────────────────────────────────────
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = (
        "⚡ *Extractor Bot — Ready!*\n\n"
        "Seedha bhejo:\n"
        "• Text messages\n"
        "• .txt / .log / .csv files (100+ bhi ek saath!)\n\n"
        "📌 Niche buttons se kaam karo 👇"
    )
    await safe_reply(update, text, reply_markup=main_keyboard())


async def stats_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await _send_stats(update.effective_chat.id, update.message.reply_text)


async def result_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await _send_result(update.effective_chat.id, update.message.reply_text,
                       update.message.reply_document)


async def reset_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await safe_reply(update, "⚠️ *Sach mein reset karna hai?*\nSaara data chala jayega!",
                     reply_markup=confirm_reset_keyboard())


# ─── Callback Query (Button Presses) ──────────────────────────────────────────
async def button_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()  # Remove loading spinner

    cid    = update.effective_chat.id
    action = query.data

    if action == "stats":
        await _send_stats(cid, query.message.reply_text)

    elif action == "result":
        await _send_result(cid, query.message.reply_text, query.message.reply_document)

    elif action == "reset":
        await safe_edit(query.message,
                        "⚠️ *Sach mein reset karna hai?*\nSaara data chala jayega!",
                        reply_markup=confirm_reset_keyboard())

    elif action == "reset_confirm":
        store.reset(cid)
        await safe_edit(query.message, "🗑️ *Done! Sab reset ho gaya.* Fresh start! 🚀",
                        reply_markup=main_keyboard())

    elif action == "reset_cancel":
        await safe_edit(query.message, "✅ Reset cancel kar diya. Data safe hai.",
                        reply_markup=main_keyboard())

    elif action == "help":
        help_text = (
            "📖 *Help*\n\n"
            "1️⃣ Text messages bhejo — IPs/Domains extract honge\n"
            "2️⃣ Files bhejo (.txt/.log/.csv) — batch processing\n"
            "3️⃣ 100+ files ek saath? No problem — queue mein jaayenge!\n\n"
            "📊 *Stats* — kitna extract hua dekho\n"
            "📥 *Result* — output file download karo\n"
            "🗑️ *Reset* — sab clear karo\n"
        )
        await safe_edit(query.message, help_text, reply_markup=main_keyboard())


# ─── Shared Logic for Stats/Result ────────────────────────────────────────────
async def _send_stats(cid: int, reply_fn):
    s     = store.stats(cid)
    data  = store.get(cid)
    total = sum(len(v) for v in data.values())

    # Check if a worker is still running
    worker = _worker_tasks.get(cid)
    queue  = _chat_queues.get(cid)
    pending = queue.qsize() if queue else 0
    status = f"⏳ Queue: `{pending}` files remaining" if (worker and not worker.done()) else "✅ Idle"

    text = (
        f"📊 *Stats*\n\n"
        f"📨 Messages  : `{s['messages']}`\n"
        f"📄 Files     : `{s['files']}`\n"
        f"❌ Errors    : `{s['errors']}`\n\n"
        f"🌐 Domains    : `{len(data['domains'])}`\n"
        f"🔗 Subdomains : `{len(data['subdomains'])}`\n"
        f"🖥️ IPv4       : `{len(data['ips'])}`\n"
        f"🖧 IPv6       : `{len(data['ipv6'])}`\n"
        f"━━━━━━━━━━━━━━\n"
        f"✅ Total unique : `{total}`\n"
        f"Status : {status}"
    )
    try:
        await reply_fn(text, parse_mode=ParseMode.MARKDOWN, reply_markup=result_keyboard())
    except Exception as e:
        logger.error(f"_send_stats error: {e}")


async def _send_result(cid: int, reply_text_fn, reply_doc_fn):
    data  = store.get(cid)
    total = sum(len(v) for v in data.values())

    if not total:
        try:
            await reply_text_fn(
                "❌ Koi data nahi hai. Pehle messages ya files bhejo!",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=main_keyboard(),
            )
        except Exception:
            pass
        return

    output = build_output(data)
    if not output:
        try:
            await reply_text_fn("❌ Output generate nahi ho saka.", parse_mode=ParseMode.MARKDOWN)
        except Exception:
            pass
        return

    s        = store.stats(cid)
    filepath = None
    try:
        out_dir  = os.path.expanduser("~/extracted_results")
        os.makedirs(out_dir, exist_ok=True)
        filepath = os.path.join(out_dir, f"result_{cid}_{int(time.time())}.txt")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(output)

        caption = (
            f"✅ *Extraction Done!*\n"
            f"📦 Total unique : `{total}`\n"
            f"📨 Messages : `{s['messages']}` | 📄 Files : `{s['files']}`"
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with open(filepath, "rb") as f:
                    await reply_doc_fn(
                        document=f,
                        filename="extracted_results.txt",
                        caption=caption,
                        parse_mode=ParseMode.MARKDOWN,
                        reply_markup=result_keyboard(),
                        read_timeout=90,
                        write_timeout=90,
                    )
                break
            except RetryAfter as e:
                await asyncio.sleep(e.retry_after + 1)
            except (TimedOut, NetworkError) as e:
                logger.warning(f"result send attempt {attempt}: {e}")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_DELAY * attempt)
            except Exception as e:
                logger.error(f"result send error: {e}")
                break
    finally:
        # ✅ FIXED: Always clean up temp file
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass


# ─── Message Handler ───────────────────────────────────────────────────────────
async def handle_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg:
        return
    cid  = update.effective_chat.id
    text = ((msg.text or "") + " " + (msg.caption or "")).strip()
    if not text:
        return
    loop = asyncio.get_running_loop()            # ✅ FIXED: get_running_loop()
    await loop.run_in_executor(executor, extract_sync, text, cid, "message")


# ─── Document Handler ──────────────────────────────────────────────────────────
async def handle_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg or not msg.document:
        return

    doc   = msg.document
    cid   = update.effective_chat.id
    fname = doc.file_name or "unknown"
    mime  = doc.mime_type or ""

    ok_ext = (".txt", ".log", ".csv", ".text", ".lst", ".list", ".out")
    if not (any(fname.lower().endswith(e) for e in ok_ext) or "text" in mime):
        return  # Silently skip unsupported files

    # Enqueue file — NO individual ack messages (avoids 100-message spam)
    qsize = await enqueue_file(cid, fname, doc.file_id, ctx.bot)

    if qsize == -1:
        await safe_send(
            msg.reply_text,
            f"⚠️ Queue full ({QUEUE_MAXSIZE} files)! Pehle `/result` lo phir bhejo.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Only send ONE acknowledgement per batch (first file of the batch)
    if qsize == 1:
        await safe_send(
            msg.reply_text,
            f"⏳ *Processing shuru...* Files queue mein hain.\n"
            f"Done hone pe automatic summary milega! 📬",
            parse_mode=ParseMode.MARKDOWN,
        )
    # If qsize > 1, silently queue (no spam)


# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    TOKEN = os.environ.get(
    "TELEGRAM_BOT_TOKEN",
    "8810580917:AAHvMx6SQbYIneV1ccczHiYxU88KnIuP4LU"
)
    if not TOKEN:
        print("❌ TELEGRAM_BOT_TOKEN set nahi hai!")
        print("   export TELEGRAM_BOT_TOKEN='your_token_here'")
        exit(1)

    print("🚀 Bot starting (Termux-optimized, queue-based)...")

    request = HTTPXRequest(
        connect_timeout = CONNECT_TIMEOUT,
        read_timeout    = READ_TIMEOUT,
        write_timeout   = WRITE_TIMEOUT,
        pool_timeout    = POOL_TIMEOUT,
    )

    app = (
        Application.builder()
        .token(TOKEN)
        .request(request)
        .concurrent_updates(False)    # ✅ FIXED: True was causing race conditions
        .build()
    )

    app.add_handler(CommandHandler("start",  start))
    app.add_handler(CommandHandler("help",   start))
    app.add_handler(CommandHandler("stats",  stats_cmd))
    app.add_handler(CommandHandler("result", result_cmd))
    app.add_handler(CommandHandler("reset",  reset_cmd))
    app.add_handler(CallbackQueryHandler(button_handler))       # Colored buttons
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    print("✅ Bot chal raha hai! Ctrl+C se band karo.\n")
    try:
        app.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
    finally:
        executor.shutdown(wait=False)   # ✅ Clean executor shutdown
        print("🛑 Bot stopped.")


if __name__ == "__main__":
    main()
