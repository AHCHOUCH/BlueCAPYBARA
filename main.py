import os
import discord
from discord.ext import commands
from dotenv import load_dotenv
from flask import Flask
from threading import Thread
import requests
import asyncio
import time

# Load environment variables
load_dotenv()

# Flask app to keep the bot alive
app = Flask(__name__)

@app.route('/')
def home():
    return "I'm alive"

def keep_alive():
    Thread(target=lambda: app.run(host='0.0.0.0', port=8080)).start()

# Bot setup with explicit intents
intents = discord.Intents.default()
intents.message_content = True  # Required for reading message content
bot = commands.Bot(command_prefix='!', intents=intents)

# VirusTotal API setup
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3/urls'

# Rate limiting setup
MAX_REQUESTS_PER_MINUTE = 4
request_times = []

async def check_rate_limit():
    now = time.time()
    request_times[:] = [t for t in request_times if now - t < 60]
    if len(request_times) >= MAX_REQUESTS_PER_MINUTE:
        await asyncio.sleep(60 - (now - request_times[0]))
    request_times.append(now)

async def scan_url(url):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    data = {"url": url}
    
    try:
        response = requests.post(VIRUSTOTAL_API_URL, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        return await get_analysis_result(result['data']['id'])
    except requests.exceptions.RequestException as e:
        return f"Error scanning URL: {str(e)}"

async def get_analysis_result(analysis_id):
    await check_rate_limit()
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for attempt in range(5):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()
            
            if result['data']['attributes']['status'] == 'completed':
                return result['data']['attributes']
            await asyncio.sleep(10)
        except requests.exceptions.RequestException as e:
            if attempt == 4:
                return f"Error getting analysis result: {str(e)}"
    
    return "Failed to get analysis result after multiple attempts."

def generate_risk_message(stats, url):
    malicious, suspicious, harmless = stats['malicious'], stats['suspicious'], stats['harmless']
    risk_level, emoji = ("High", "🚨") if malicious > 0 else ("Medium", "⚠️") if suspicious > 0 else ("Low", "✅")
    
    risk_message = (f"{emoji} **URL Risk Assessment**\n\n**URL:** {url}\n**Risk Level: {risk_level}**\n\n"
                    f"**Scan Results:**\n- Malicious: {malicious}\n- Suspicious: {suspicious}\n- Clean: {harmless}\n\n")
    
    if risk_level != "Low":
        risk_message += ("**Potential Risks:**\n- Malware infection\n- Phishing attempt\n- Data theft\n"
                         "⚠️ **WARNING:** Visiting this URL may put your system and personal information at risk. Proceed with caution!")
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

    scanned_urls = set()  # To keep track of URLs we've already scanned in this message
    for word in message.content.split():
        if word.startswith(('http://', 'https://')) and word not in scanned_urls:
            scanned_urls.add(word)
            scanning_message = await message.channel.send(f"🔍 Scanning URL: {word}")
            result = await scan_url(word)
            
            if isinstance(result, dict):
                stats = result['stats']
                await scanning_message.edit(content=generate_risk_message(stats, word))
                
                if stats['malicious'] > 0:
                    announcement_channel = discord.utils.get(message.guild.channels, name='announcement')
                    if announcement_channel:
                        announcement = (f"🚨 **Malicious URL Alert**\n\nUser {message.author.mention} posted a malicious URL in "
                                        f"{message.channel.mention}.\nURL: {word}\nMalicious detections: {stats['malicious']}\n"
                                        f"Suspicious detections: {stats['suspicious']}\n\nPlease take appropriate action.")
                        await announcement_channel.send(announcement)
            else:
                await scanning_message.edit(content=result)

    await bot.process_commands(message)

# Start the Flask server to keep the bot alive
keep_alive()

# Run the bot
if (token := os.getenv('DISCORD_TOKEN')):
    bot.run(token)
else:
    print("Error: DISCORD_TOKEN not found in environment variables")
