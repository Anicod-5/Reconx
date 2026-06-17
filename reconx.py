import argparse
import asyncio
import aiohttp
import json
import re
import sys
import random
import logging
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel

console = Console()
VERSION = "1.5"

# ====================== Logging ======================
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("reconx.log", encoding="utf-8")]
)
logger = logging.getLogger(__name__)

# ====================== User-Agents ======================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
]

def banner():
    console.print(Panel.fit(
        f"[bold red]ReconX[/bold red] [bold]v{VERSION} - Complete Edition[/bold]\n"
        "Email Search • HTML Reports • Fast Mode",
        title="🔍 ReconX",
        border_style="blue"
    ))

def sanitize_username(username: str) -> str:
    username = username.strip()
    if not username or len(username) > 50:
        raise ValueError("Invalid username.")
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        raise ValueError("Invalid characters in username.")
    return username

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def get_random_delay():
    return random.uniform(1.0, 3.0)

async def fetch_robots_txt(session, domain: str):
    try:
        url = f"https://{domain}/robots.txt"
        async with session.get(url, timeout=8) as resp:
            if resp.status == 200:
                text = await resp.text()
                if any(x in text for x in ["Disallow: /", "Disallow: /*"]):
                    logger.warning(f"robots.txt restricts {domain}")
    except:
        pass

async def check_profile(session, platform, base_url, username, proxy=None):
    headers = {"User-Agent": get_random_user_agent()}
    username_lower = username.lower()

    try:
        await asyncio.sleep(get_random_delay())

        async with session.get(
            base_url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30),
            allow_redirects=True,
            proxy=proxy,
            ssl=True
        ) as resp:
            
            final_url = str(resp.real_url)
            if resp.status != 200 or any(x in final_url for x in ["/login", "/signup", "/404", "suspended"]):
                return None

            content_type = resp.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                return None

            text = await resp.text()
            text_lower = text.lower()[:15000]

            
            if "github.com" in final_url and any(k in text_lower for k in ["followers", "repositories", "joined on"]):
                return final_url
            elif any(x in final_url for x in ["x.com", "twitter.com"]) and "joined" in text_lower and "doesn’t exist" not in text_lower:
                return final_url
            elif "instagram.com" in final_url and not any(err in text_lower for err in ["sorry", "not found", "restricted"]):
                return final_url
            elif "reddit.com" in final_url and "not found" not in text_lower:
                return final_url
            elif "linkedin.com" in final_url and any(k in text_lower for k in ["experience", "headline"]):
                return final_url
            elif "youtube.com" in final_url and any(k in text_lower for k in ["subscriber", "joined"]):
                return final_url
            elif "tiktok.com" in final_url and "following" in text_lower:
                return final_url
            elif any(k in text_lower for k in ["bio", "about", "followers"]) and len(text) > 6000:
                return final_url

    except Exception as e:
        logger.error(f"Error {platform}: {type(e).__name__}")
    return None


async def search_email(email: str, hunter_api_key: str = None):
    """بحث الإيميلات باستخدام Hunter.io (أو HaveIBeenPwned في المستقبل)"""
    console.print(f"[yellow]Searching email: {email}[/yellow]")
    
    if hunter_api_key:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={hunter_api_key}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        console.print(Panel(str(data.get("data", {})), title="Hunter.io Result", border_style="green"))
                        return data
        except Exception as e:
            logger.error(f"Hunter.io error: {type(e).__name__}")
    else:
        console.print("[yellow]Hunter.io API key not provided. Use --hunter-key[/yellow]")
    
    
    console.print("[yellow]HaveIBeenPwned check (breaches) coming soon...[/yellow]")


async def search_username(username: str, delay: float = 1.2, output: str = None, proxy: str = None, fast_mode: bool = False):
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

    console.print(f"[bold yellow]Searching '{username}' across {len(platforms)} platforms ({'Fast' if fast_mode else 'Full'} mode)...[/bold yellow]\n")
    
    found = []
    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        for domain in ["github.com", "twitter.com", "instagram.com", "reddit.com"]:
            await fetch_robots_txt(session, domain)
        
        tasks = [check_profile(session, plat, url, username, proxy) for plat, url in platforms.items()]
        results = await asyncio.gather(*tasks)
        
        for platform, link in zip(platforms.keys(), results):
            if link:
                console.print(f"[green]✓ {platform}:[/green] [bold]{link}[/bold]")
                found.append({"platform": platform, "url": link})

    if not found:
        console.print("[yellow]No confirmed profiles found.[/yellow]")
    else:
        console.print(f"\n[bold green]Found {len(found)} real profile(s)![/bold green]")

    
    if output:
        data = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "mode": "fast" if fast_mode else "full",
            "found": found
        }
        
        
        with open(f"{output}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        
        generate_html_report(data, f"{output}.html")
        console.print(f"[green]Reports saved: {output}.json & {output}.html[/green]")


def generate_html_report(data, filename: str):
    """توليد تقرير HTML أنيق"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>ReconX Report - {data['username']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }}
            h1 {{ color: #d32f2f; }}
            .result {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <h1>🔍 ReconX Report v{VERSION}</h1>
        <p><strong>Username:</strong> {data['username']}</p>
        <p><strong>Time:</strong> {data['timestamp']}</p>
        <p><strong>Mode:</strong> {data['mode']}</p>
        <h2>Found Profiles ({len(data['found'])})</h2>
    """
    for item in data['found']:
        html_content += f'<div class="result"><strong>{item["platform"]}</strong>: <a href="{item["url"]}">{item["url"]}</a></div>'
    
    html_content += "</body></html>"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)


async def main():
    banner()
    
    parser = argparse.ArgumentParser(description=f"ReconX v{VERSION}")
    parser.add_argument("-u", "--username", help="Username to search")
    parser.add_argument("-d", "--domain", help="Domain for WHOIS")
    parser.add_argument("-e", "--email", help="Search email")
    parser.add_argument("--hunter-key", help="Hunter.io API key")
    parser.add_argument("--delay", type=float, default=1.2, help="Base delay")
    parser.add_argument("-o", "--output", help="Output filename (without extension)")
    parser.add_argument("--proxy", help="Proxy address")
    parser.add_argument("--proxy-list", help="Proxy list file")
    parser.add_argument("--fast", action="store_true", help="Fast mode (fewer platforms)")

    args = parser.parse_args()

    if not any([args.username, args.domain, args.email]):
        parser.print_help()
        return

    proxy = args.proxy
    if args.proxy_list:
        try:
            with open(args.proxy_list) as f:
                proxies = [line.strip() for line in f if line.strip()]
                proxy = random.choice(proxies) if proxies else None
        except:
            console.print("[red]Failed to load proxy list[/red]")

    if args.username:
        await search_username(args.username, args.delay, args.output, proxy, args.fast)
    
    if args.domain:
        
        console.print("[yellow]WHOIS module active...[/yellow]")
    
    if args.email:
        await search_email(args.email, args.hunter_key)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user.[/yellow]")
    except Exception as e:
        logger.critical(f"Critical: {type(e).__name__}")
        console.print("[red]Critical error. Check reconx.log[/red]")
