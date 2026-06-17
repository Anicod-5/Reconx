

import argparse
import asyncio
import aiohttp
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

def banner():
    console.print(Panel.fit(
        "[bold red]ReconX[/bold red] [bold]v3.0 - Fixed & Improved[/bold]\n"
        "Better Detection • Reduced False Positives",
        title="🔍 ReconX",
        border_style="blue"
    ))

async def check_profile(session, platform, url, username, delay=0.8):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }
    username_lower = username.lower().strip()
    
    try:
        await asyncio.sleep(delay)
        async with session.get(url, headers=headers, timeout=15, allow_redirects=True) as resp:
            if resp.status != 200:
                return None
            
            text = await resp.text()
            text_lower = text.lower()
            
            
            if "github.com" in url:
                if (username_lower in text_lower and 
                    any(k in text_lower for k in ["followers", "repositories", "contributions"])):
                    return url
                    
            elif "x.com" in url or "twitter.com" in url:
                if (username_lower in text_lower and 
                    "this account doesn" not in text_lower and 
                    "suspended" not in text_lower):
                    return url
                    
            elif "instagram.com" in url:
                if (username_lower in text_lower and 
                    "sorry, this page" not in text_lower and 
                    "page not found" not in text_lower):
                    return url
                    
            elif "reddit.com" in url:
                if ((f"u/{username_lower}" in text_lower or f"/user/{username_lower}" in text_lower) and 
                    "page not found" not in text_lower):
                    return url
                    
            elif "linkedin.com" in url:
                if (username_lower in text_lower and 
                    any(k in text_lower for k in ["profile", "experience", "about"])):
                    return url
                    
            elif "youtube.com" in url:
                if (username_lower in text_lower and 
                    any(k in text_lower for k in ["subscriber", "channel", "videos"])):
                    return url
                    
            elif "tiktok.com" in url:
                if (username_lower in text_lower and 
                    "couldn't find this account" not in text_lower):
                    return url
                    
            
            elif (username_lower in text_lower and 
                  len(text) > 5000 and 
                  any(k in text_lower for k in ["profile", "bio", "about"])):
                return url
                
    except Exception:
        pass  
    return None

async def search_username(username, delay=0.8, output=None):
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "X/Twitter": f"https://x.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Medium": f"https://medium.com/@{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Behance": f"https://www.behance.net/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Patreon": f"https://www.patreon.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Telegram": f"https://t.me/{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
    }

    console.print(f"[bold yellow]Searching '{username}' across {len(platforms)} platforms...[/bold yellow]\n")
    
    found = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_profile(session, plat, url, username, delay) for plat, url in platforms.items()]
        results = await asyncio.gather(*tasks)
        
        for platform, link in zip(platforms.keys(), results):
            if link:
                console.print(f"[green]✓ {platform}:[/green] [bold]{link}[/bold]")
                found.append({"platform": platform, "url": link})
    
    if not found:
        console.print("[yellow]No confirmed profiles found.[/yellow]")
    else:
        console.print(f"\n[bold green]Found {len(found)} real profile(s)![/bold green]")
    
    if output and found:
        data = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "found": found
        }
        with open(f"{output}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Saved to {output}.json[/green]")

def whois_lookup(domain):
    console.print(f"[yellow]Fetching WHOIS for {domain}...[/yellow]")
    try:
        import whois
        w = whois.whois(domain)
        console.print(Panel(str(w), title="WHOIS Result", border_style="green"))
    except ImportError:
        console.print("[red]Install python-whois: pip install python-whois[/red]")
    except Exception as e:
        console.print(f"[red]WHOIS Error: {e}[/red]")

async def main():
    banner()
    
    parser = argparse.ArgumentParser(description="ReconX v1.0")
    parser.add_argument("-u", "--username", help="Username to search")
    parser.add_argument("-d", "--domain", help="Domain for WHOIS")
    parser.add_argument("--delay", type=float, default=0.8, help="Delay between requests")
    parser.add_argument("-o", "--output", help="Output JSON filename (without .json)")
    
    args = parser.parse_args()
    
    if not args.username and not args.domain:
        parser.print_help()
        return
    
    if args.username:
        await search_username(args.username, args.delay, args.output)
    
    if args.domain:
        whois_lookup(args.domain)

if __name__ == "__main__":
    asyncio.run(main())
