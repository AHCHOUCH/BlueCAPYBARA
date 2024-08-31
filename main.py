import os
from dotenv import load_dotenv
import discord
from discord.ext import commands
import aiohttp
import asyncio
from flask import Flask
from threading import Thread
import time
from collections import deque

# Load environment variables
load_dotenv()

# Flask app to keep the bot alive
app = Flask('')

@app.route('/')
def home():
    return "I'm alive"

def run():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    Thread(target=run).start()

# Bot setup with explicit intents
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# VirusTotal API setup
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3/urls'

# Rate limiting setup
MAX_REQUESTS_PER_MINUTE = 4
request_times = deque(maxlen=MAX_REQUESTS_PER_MINUTE)

async def check_rate_limit():
    now = time.time()
    if len(request_times) == MAX_REQUESTS_PER_MINUTE:
        if now - request_times[0] < 60:
            await asyncio.sleep(60 - (now - request_times[0]))
    request_times.append(time.time())

async def scan_url(session, url):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    data = {"url": url}
    
    try:
        async with session.post(VIRUSTOTAL_API_URL, headers=headers, data=data) as response:
            response.raise_for_status()
            result = await response.json()
            analysis_id = result['data']['id']
            return await get_analysis_result(session, analysis_id)
    except aiohttp.ClientError as e:
        print(f"Error in scan_url: {str(e)}")
        return f"Error scanning URL: {str(e)}"

async def get_analysis_result(session, analysis_id):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    max_retries = 5
    retry_delay = 10

    for attempt in range(max_retries):
        try:
            async with session.get(url, headers=headers) as response:
                response.raise_for_status()
                result = await response.json()
                
                status = result['data']['attributes']['status']
                if status == 'completed':
                    return result['data']['attributes']
                elif status in ('queued', 'in-progress'):
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay)
                        continue
                    else:
                        return "Analysis is still in progress. Please try again later."
        except aiohttp.ClientError as e:
            print(f"Error in get_analysis_result (attempt {attempt + 1}): {str(e)}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                return f"Error getting analysis result after {max_retries} attempts: {str(e)}"

    return "Failed to get analysis result after multiple attempts."

def generate_risk_message(stats, url):
    malicious = stats['malicious']
    suspicious = stats['suspicious']
    
    risk_level = "High" if malicious > 0 else "Medium" if suspicious > 0 else "Low"
    emoji = "🚨" if malicious > 0 else "⚠️" if suspicious > 0 else "✅"
    
    potential_risks = [
        "Malware infection",
        "Phishing attempt",
        "Data theft",
        "Identity theft",
        "Financial fraud"
    ]
    
    risk_message = (
        f"{emoji} **URL Risk Assessment**\n\n"
        f"**URL:** {url}\n"
        f"**Risk Level: {risk_level}**\n\n"
        f"**Scan Results:**\n"
        f"- Malicious: {malicious}\n"
        f"- Suspicious: {suspicious}\n"
        f"- Clean: {stats['harmless']}\n\n"
    )
    
    if risk_level != "Low":
        risk_message += (
            "**Potential Risks:**\n" +
            "\n".join(f"- {risk}" for risk in potential_risks[:3]) +
            "\n\n⚠️ **WARNING:** Visiting this URL may put your system and personal information at risk. Proceed with caution!"
        )
    else:
        risk_message += "✅ This URL appears to be safe, but always exercise caution when clicking on links."
    
    return risk_message

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    words = message.content.split()
    scanned_urls = set()
    async with aiohttp.ClientSession() as session:
        tasks = []
        for word in words:
            if word.startswith(('http://', 'https://')) and word not in scanned_urls:
                scanned_urls.add(word)
                tasks.append(asyncio.create_task(scan_and_report(session, message.channel, word, message.author, message.guild)))
        
        if tasks:
            await asyncio.gather(*tasks)

    await bot.process_commands(message)

async def scan_and_report(session, channel, url, author, guild):
    scanning_message = await channel.send(f"🔍 Scanning URL: {url}")
    result = await scan_url(session, url)
    
    if isinstance(result, dict):
        stats = result['stats']
        risk_message = generate_risk_message(stats, url)
        await scanning_message.edit(content=risk_message)
        
        if stats['malicious'] > 0:
            await send_announcement(guild, author, channel, url, stats)
    else:
        await scanning_message.edit(content=result)

async def send_announcement(guild, author, channel, url, stats):
    announcement_channel = discord.utils.get(guild.channels, name='announcement')
    if announcement_channel:
        announcement = (
            f"🚨 **Malicious URL Alert**\n\n"
            f"User {author.mention} posted a malicious URL in {channel.mention}.\n"
            f"URL: {url}\n"
            f"Malicious detections: {stats['malicious']}\n"
            f"Suspicious detections: {stats['suspicious']}\n\n"
            "Please take appropriate action."
        )
        await announcement_channel.send(announcement)
                else:
                    await scanning_message.edit(content=result)

    await bot.process_commands(message)

# Start the Flask server
keep_alive()

# Run the bot
token = os.getenv('DISCORD_TOKEN')
if token:
    bot.run(token)
else:
    print("Error: DISCORD_TOKEN not found in environment variables")
