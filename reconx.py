import argparse
import asyncio
import aiohttp
import json
import re
import sys
import random
import logging
import os
import platform
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
import html

console = Console()
VERSION = "1.9.2"

# ====================== Platform Detection ======================
IS_TERMUX = "TERMUX" in os.environ
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"
IS_WINDOWS = os.name == "nt"

# ====================== Security Config ======================
MAX_CONCURRENCY = 20 if IS_TERMUX else 30
MAX_RESPONSE_SIZE = 500_000  # 500 KB
LOCAL_ADDRESSES = {'127.0.0.1', 'localhost', '::1', '0.0.0.0', '[::1]', '10.', '172.16.', '192.168.'}

# ====================== Logging ======================
log_file = Path("reconx.log")
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(log_file, encoding="utf-8")]
)
logger = logging.getLogger(__name__)

# Safe permissions
try:
    if os.name == 'posix' and not IS_TERMUX:
        os.chmod(log_file, 0o600)
except Exception:
    pass

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
]

def banner():
    console.print(Panel.fit(
        f"[bold red]ReconX[/bold red] [bold]v{VERSION} - Secure Cross-Platform[/bold]\n"
        "Termux • Kali • Linux • macOS • Windows",
        title="🔍 ReconX",
        border_style="red"
    ))

def sanitize_username(username: str) -> str:
    username = username.strip()
    if not username or len(username) > 50:
        raise ValueError("Invalid username: must be 1-50 characters.")
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        raise ValueError("Invalid characters in username.")
    return username

def sanitize_output_path(filename: str) -> Path:
    if not filename:
        return Path("reconx_report")
    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)[:100] or "reconx_report"
    path = Path(safe_name)
    if path.is_absolute() or ".." in str(path) or any(local in str(path).lower() for local in LOCAL_ADDRESSES):
        console.print("[yellow]Warning: Suspicious output path, using default.[/yellow]")
        return Path("reconx_report")
    return path

def is_safe_proxy(proxy: str) -> bool:
    if not proxy:
        return False
    p = proxy.lower().strip()
    if any(local in p for local in LOCAL_ADDRESSES):
        console.print("[red]Blocked dangerous proxy (SSRF Protection)[/red]")
        return False
    if not re.match(r'^(https?|socks5?)(://)?', p):
        console.print("[red]Invalid proxy format. Use http:// or socks5://[/red]")
        return False
    return True

async def test_proxy(proxy: str, timeout: int = 10) -> bool:
    console.print(f"[blue]Testing proxy: {proxy}[/blue]")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy) as resp:
                if resp.status == 200:
                    console.print("[green]✓ Proxy is working[/green]")
                    return True
    except Exception:
        console.print("[red]Proxy test failed[/red]")
    return False

async def check_profile(session, platform_name, base_url, username, proxy=None):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        await asyncio.sleep(random.uniform(0.8, 2.2))
        async with session.get(
            base_url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=25, sock_connect=10),
            allow_redirects=True,
            proxy=proxy,
            ssl=True
        ) as resp:
            
            final_url = str(resp.real_url).lower()
            if resp.status != 200 or any(x in final_url for x in ["/login", "/signup", "/404", "suspended", "error", "blocked"]):
                return None

            text = await resp.text()
            if len(text) > MAX_RESPONSE_SIZE:
                text = text[:MAX_RESPONSE_SIZE]
            text_lower = text.lower()[:28000]

            # Strong checks for Instagram & Twitter
            if "instagram.com" in final_url and not any(err in text_lower for err in ["sorry", "not found", "restricted", "login required", "page not available"]):
                return str(resp.real_url)
            elif any(x in final_url for x in ["x.com", "twitter.com"]) and any(k in text_lower for k in ["joined", "followers", "following"]) and "doesn’t exist" not in text_lower:
                return str(resp.real_url)
            elif "github.com" in final_url and any(k in text_lower for k in ["followers", "repositories", "joined"]):
                return str(resp.real_url)
            elif any(k in text_lower for k in ["bio", "about", "followers", "following", "joined"]) and len(text) > 7000:
                return str(resp.real_url)
    except Exception as e:
        logger.debug(f"Error on {platform_name}: {type(e).__name__}")
    return None

def get_platforms(fast_mode: bool):
    platforms = {
        "GitHub": "https://github.com/{username}",
        "X/Twitter": "https://x.com/{username}",
        "Instagram": "https://www.instagram.com/{username}/",
        "Reddit": "https://www.reddit.com/user/{username}",
        "LinkedIn": "https://www.linkedin.com/in/{username}",
        "YouTube": "https://www.youtube.com/@{username}",
        "TikTok": "https://www.tiktok.com/@{username}",
        "Twitch": "https://www.twitch.tv/{username}",
        "Medium": "https://medium.com/@{username}",
        "GitLab": "https://gitlab.com/{username}",
    }
    if not fast_mode:
        platforms.update({
            "Facebook": "https://www.facebook.com/{username}",
            "Pinterest": "https://www.pinterest.com/{username}/",
            "Behance": "https://www.behance.net/{username}",
            "Dribbble": "https://dribbble.com/{username}",
        })
    return platforms

async def search_username(username: str, output: str = None, proxy: str = None, fast_mode: bool = False, concurrency: int = 10):
    try:
        username = sanitize_username(username)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    platforms = get_platforms(fast_mode)
    console.print(f"[bold yellow]Searching '{username}' across {len(platforms)} platforms...[/bold yellow]\n")

    found = []
    concurrency = min(concurrency, MAX_CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=concurrency * 2, ssl=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_profile(session, plat, url.format(username=username), username, proxy) 
                 for plat, url in platforms.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for platform, result in zip(platforms.keys(), results):
            if isinstance(result, Exception) or not result:
                continue
            console.print(f"[green]✓ {platform}:[/green] [bold]{result}[/bold]")
            found.append({"platform": platform, "url": result})

    if output:
        safe_path = sanitize_output_path(output)
        data = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "found": found
        }
        json_path = safe_path.with_suffix(".json")
        html_path = safe_path.with_suffix(".html")

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Simple secure HTML report
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ReconX - {html.escape(username)}</title>
<style>body{{font-family:Arial;background:#f4f4f4;}} .result{{background:white;padding:15px;margin:10px;border-radius:8px;}}</style>
</head><body><h1>ReconX Report v{VERSION}</h1>
<p><strong>Username:</strong> {html.escape(username)}</p>
<h2>Found Profiles ({len(found)})</h2>""")
            for item in found:
                f.write(f'<div class="result"><strong>{html.escape(item["platform"])}</strong>: <a href="{html.escape(item["url"])}" target="_blank">{html.escape(item["url"])}</a></div>')
            f.write("</body></html>")

        console.print(f"[green]✅ Reports saved: {json_path} & {html_path}[/green]")

async def main():
    banner()
    parser = argparse.ArgumentParser(description=f"ReconX v{VERSION}")
    parser.add_argument("-u", "--username", required=True, help="Username to search")
    parser.add_argument("-o", "--output", help="Output filename (without extension)")
    parser.add_argument("--fast", action="store_true", help="Fast mode")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests")
    parser.add_argument("--proxy", help="Proxy (http:// or socks5://)")
    parser.add_argument("--test-proxy", action="store_true", help="Test proxy")

    args = parser.parse_args()

    proxy = args.proxy
    if proxy:
        if not is_safe_proxy(proxy):
            proxy = None
        elif args.test_proxy:
            if not await test_proxy(proxy):
                proxy = None

    await search_username(args.username, args.output, proxy, args.fast, args.concurrency)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
    except Exception as e:
        logger.critical(f"Critical error: {type(e).__name__}")
        console.print("[red]Critical error occurred. Check reconx.log[/red]")
