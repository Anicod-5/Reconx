import argparse
import asyncio
import aiohttp
import json
import re
import sys
import random
import logging
import os
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
import html

console = Console()
VERSION = "1.7"

log_file = Path("reconx.log")
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(log_file, encoding="utf-8")]
)
logger = logging.getLogger(__name__) 

try:
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
        f"[bold red]ReconX[/bold red] [bold]v{VERSION} - Complete Edition[/bold]\n"
        "Email Search • HTML Reports • Proxy Support • SOCKS5",
        title="🔍 ReconX",
        border_style="blue"
    ))

def sanitize_username(username: str) -> str:
    """Sanitize username with improved validation."""
    username = username.strip()
    if not username or len(username) > 50:
        raise ValueError("Invalid username: too short or too long.")
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        raise ValueError("Invalid characters in username. Only alphanumeric, ., _, - allowed.")
    return username

def sanitize_output_path(filename: str) -> Path:
    """Secure output path sanitization to prevent path traversal."""
    if not filename:
        return Path("reconx_report")
    
    safe_name = re.sub(r'[^a-zA-Z0-9._-]+', '_', filename)
    safe_name = safe_name[:100].strip('_')
    if not safe_name:
        safe_name = "reconx_report"
    path = Path(safe_name)
    
    if path.is_absolute() or ".." in str(path):
        console.print("[yellow]Warning: Invalid output path detected. Using default.[/yellow]")
        return Path("reconx_report")
    return path

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def get_random_delay():
    return random.uniform(0.8, 2.5)

async def test_proxy(proxy: str, timeout: int = 10) -> bool:
    """Test proxy connectivity before use."""
    console.print(f"[blue]Testing proxy: {proxy}[/blue]")
    try:
        connector = aiohttp.TCPConnector(ssl=True)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy) as resp:
                if resp.status == 200:
                    console.print("[green]✓ Proxy is working[/green]")
                    return True
                else:
                    console.print(f"[red]✗ Proxy returned status {resp.status}[/red]")
                    return False
    except Exception as e:
        console.print(f"[red]✗ Proxy test failed: {type(e).__name__}[/red]")
        logger.warning(f"Proxy test failed for {proxy}: {e}")
        return False

def validate_proxy(proxy: str) -> bool:
    """Improved proxy validation supporting HTTP, HTTPS, and SOCKS5."""
    if not proxy:
        return False
    proxy = proxy.strip()
    if re.match(r'^(https?|socks5?)(://)?', proxy.lower()):
        return True
    console.print("[red]Invalid proxy format. Use: http://... or socks5://...[/red]")
    return False

async def fetch_robots_txt(session, domain: str):
    """Improved robots.txt check."""
    try:
        url = f"https://{domain}/robots.txt"
        async with session.get(url, timeout=8) as resp:
            if resp.status == 200:
                text = await resp.text()
                if any(x in text.lower() for x in ["disallow: /", "disallow: /*"]):
                    logger.warning(f"robots.txt restricts {domain}")
    except Exception:
        pass

async def check_profile(session, platform, base_url, username, proxy=None):
    """Improved profile checker with reduced false positives."""
    headers = {"User-Agent": get_random_user_agent()}
    try:
        await asyncio.sleep(get_random_delay())

        async with session.get(
            base_url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=25, sock_connect=10),
            allow_redirects=True,
            proxy=proxy,
            ssl=True
        ) as resp:
            
            final_url = str(resp.real_url).lower()
            status = resp.status
            
            if status != 200 or any(x in final_url for x in ["/login", "/signup", "/404", "suspended", "unavailable", "error"]):
                return None

            content_type = resp.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type and 'application/json' not in content_type:
                return None

            text = await resp.text()
            if len(text) > 500000:
                text = text[:500000]
            text_lower = text.lower()[:25000]

            
            if "github.com" in final_url and any(k in text_lower for k in ["followers", "repositories", "joined on", "contributions"]):
                return str(resp.real_url)
            elif any(x in final_url for x in ["x.com", "twitter.com"]) and ("joined" in text_lower or "followers" in text_lower) and "doesn’t exist" not in text_lower and "this account" not in text_lower:
                return str(resp.real_url)
            elif "instagram.com" in final_url and not any(err in text_lower for err in ["sorry", "not found", "page not available", "restricted", "login"]):
                return str(resp.real_url)
            elif "reddit.com" in final_url and "not found" not in text_lower and ("karma" in text_lower or "joined" in text_lower):
                return str(resp.real_url)
            elif "linkedin.com" in final_url and any(k in text_lower for k in ["experience", "headline", "about", "connections"]):
                return str(resp.real_url)
            elif "youtube.com" in final_url and any(k in text_lower for k in ["subscriber", "joined", "videos", "about"]):
                return str(resp.real_url)
            elif "tiktok.com" in final_url and any(k in text_lower for k in ["following", "followers", "likes", "bio"]):
                return str(resp.real_url)
            
            elif any(k in text_lower for k in ["bio", "about", "followers", "following", "profile is private"]) and len(text) > 5000:
                return str(resp.real_url)

    except Exception as e:
        logger.debug(f"Profile check error {platform}: {type(e).__name__}")
    return None

async def search_email(email: str, hunter_api_key: str = None):
    """Email search with validation."""
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        console.print("[red]Invalid email format.[/red]")
        return

    console.print(f"[yellow]Searching email: {email}[/yellow]")
    
    if hunter_api_key:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={hunter_api_key}"
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        console.print(Panel(str(data.get("data", {})), title="Hunter.io Result", border_style="green"))
                        return data
        except Exception as e:
            logger.error(f"Hunter.io error: {e}")
    else:
        console.print("[yellow]Hunter.io API key not provided. Use --hunter-key[/yellow]")

async def search_username(username: str, delay: float = 1.2, output: str = None, proxy: str = None, fast_mode: bool = False, concurrency: int = 10):
    """Core search with concurrency control."""
    try:
        username = sanitize_username(username)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    platforms = {
        "GitHub": f"https://github.com/{username}",
        "X/Twitter": f"https://x.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Medium": f"https://medium.com/@{username}",
        "GitLab": f"https://gitlab.com/{username}",
    }

    if not fast_mode:
        platforms.update({
            "Facebook": f"https://www.facebook.com/{username}",
            "Pinterest": f"https://www.pinterest.com/{username}/",
            "Behance": f"https://www.behance.net/{username}",
            "Dribbble": f"https://dribbble.com/{username}",
            "Tumblr": f"https://{username}.tumblr.com",
            "Patreon": f"https://www.patreon.com/{username}",
            "Keybase": f"https://keybase.io/{username}",
            "Telegram": f"https://t.me/{username}",
            "Snapchat": f"https://www.snapchat.com/add/{username}",
        })

    console.print(f"[bold yellow]Searching '{username}' across {len(platforms)} platforms ({'Fast' if fast_mode else 'Full'} mode, concurrency={concurrency})...[/bold yellow]\n")
    
    found = []
    connector = aiohttp.TCPConnector(limit=concurrency * 2, ttl_dns_cache=300, ssl=True)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        for domain in ["github.com", "twitter.com", "instagram.com", "reddit.com", "linkedin.com"]:
            await fetch_robots_txt(session, domain)
        
        tasks = [check_profile(session, plat, url, username, proxy) for plat, url in platforms.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for platform, result in zip(platforms.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"Task failed for {platform}: {result}")
                continue
            if result:
                console.print(f"[green]✓ {platform}:[/green] [bold]{result}[/bold]")
                found.append({"platform": platform, "url": result})

    if not found:
        console.print("[yellow]No confirmed profiles found.[/yellow]")
    else:
        console.print(f"\n[bold green]Found {len(found)} real profile(s)![/bold green]")

    if output:
        safe_path = sanitize_output_path(output)
        data = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "mode": "fast" if fast_mode else "full",
            "concurrency": concurrency,
            "found": found
        }
        
        json_path = safe_path.with_suffix(".json")
        html_path = safe_path.with_suffix(".html")
        
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            generate_html_report(data, str(html_path))
            console.print(f"[green]Reports saved: {json_path} & {html_path}[/green]")
        except Exception as e:
            logger.error(f"Failed to write reports: {e}")
            console.print("[red]Failed to save reports.[/red]")

def generate_html_report(data, filename: str):
    """Improved secure HTML report generation."""
    escaped_username = html.escape(str(data.get('username', '')))
    escaped_timestamp = html.escape(str(data.get('timestamp', '')))
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>ReconX Report - {escaped_username}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }}
            h1 {{ color: #d32f2f; }}
            .result {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            a {{ color: #1976d2; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <h1>🔍 ReconX Report v{VERSION}</h1>
        <p><strong>Username:</strong> {escaped_username}</p>
        <p><strong>Time:</strong> {escaped_timestamp}</p>
        <p><strong>Mode:</strong> {data.get('mode', 'full')}</p>
        <p><strong>Concurrency:</strong> {data.get('concurrency', 10)}</p>
        <h2>Found Profiles ({len(data.get('found', []))})</h2>
    """
    for item in data.get('found', []):
        escaped_platform = html.escape(str(item.get("platform", "")))
        escaped_url = html.escape(str(item.get("url", "")))
        html_content += f'<div class="result"><strong>{escaped_platform}</strong>: <a href="{escaped_url}" target="_blank" rel="noopener">{escaped_url}</a></div>'
    
    html_content += """
    <footer style="margin-top: 40px; color: #666; font-size: 0.9em;">
        Generated by ReconX - For educational and OSINT purposes only.
    </footer>
    </body></html>"""
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception as e:
        logger.error(f"HTML generation failed: {e}")

async def main():
    banner()
    
    parser = argparse.ArgumentParser(description=f"ReconX v{VERSION}")
    parser.add_argument("-u", "--username", help="Username to search")
    parser.add_argument("-d", "--domain", help="Domain for WHOIS (placeholder)")
    parser.add_argument("-e", "--email", help="Search email")
    parser.add_argument("--hunter-key", help="Hunter.io API key")
    parser.add_argument("--delay", type=float, default=1.2, help="Base delay between requests")
    parser.add_argument("-o", "--output", help="Output filename base (without extension)")
    parser.add_argument("--proxy", help="Proxy address (http:// or socks5://)")
    parser.add_argument("--proxy-list", help="Proxy list file (one per line, supports # comments)")
    parser.add_argument("--fast", action="store_true", help="Fast mode (fewer platforms)")
    parser.add_argument("--concurrency", type=int, default=10, help="Maximum concurrent requests (default: 10)")
    parser.add_argument("--test-proxy", action="store_true", help="Test proxy before use")

    args = parser.parse_args()

    if not any([args.username, args.domain, args.email]):
        parser.print_help()
        return

    
    proxy = args.proxy
    if args.proxy_list:
        try:
            proxy_path = Path(args.proxy_list)
            if proxy_path.exists():
                with open(proxy_path) as f:
                    proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if proxies:
                    proxy = random.choice(proxies)
                    console.print(f"[blue]Selected random proxy from list[/blue]")
            else:
                console.print("[yellow]Proxy list file not found.[/yellow]")
        except Exception as e:
            console.print(f"[red]Proxy list error: {e}[/red]")

    if proxy and validate_proxy(proxy):
        if args.test_proxy:
            if not await test_proxy(proxy):
                console.print("[yellow]Continuing without proxy...[/yellow]")
                proxy = None
        else:
            console.print(f"[blue]Using proxy: {proxy}[/blue]")
    elif proxy:
        proxy = None

    if args.username:
        await search_username(
            args.username, 
            args.delay, 
            args.output, 
            proxy, 
            args.fast, 
            args.concurrency
        )
    
    if args.domain:
        console.print("[yellow]WHOIS module coming soon...[/yellow]")
    
    if args.email:
        await search_email(args.email, args.hunter_key)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user.[/yellow]")
    except Exception as e:
        logger.critical(f"Critical error: {type(e).__name__} - {str(e)[:200]}")
        console.print("[red]Critical error. Check reconx.log for details.[/red]")
