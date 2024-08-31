import os
from dotenv import load_dotenv
import discord
from discord.ext import commands
import requests
import asyncio
from flask import Flask
from threading import Thread
import json
import time

# Load environment variables
load_dotenv()

# Debug: Print environment variables
print("Environment Variables:")
print(f"DISCORD_TOKEN: {os.getenv('DISCORD_TOKEN')}")
print(f"VIRUSTOTAL_API_KEY: {os.getenv('VIRUSTOTAL_API_KEY')}")

# Flask app to keep the bot alive
app = Flask('')

@app.route('/')
def home():
    return "I'm alive"

def run():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    t = Thread(target=run)
    t.start()

# Bot setup with explicit intents
intents = discord.Intents.default()
intents.message_content = True
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
        wait_time = 60 - (now - request_times[0])
        await asyncio.sleep(wait_time)
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
        analysis_id = result['data']['id']
        return await get_analysis_result(analysis_id)
    except requests.exceptions.RequestException as e:
        print(f"Error in scan_url: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.content}")
        return f"Error scanning URL: {str(e)}"

async def get_analysis_result(analysis_id):
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
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()
            
            status = result['data']['attributes']['status']
            if status == 'completed':
                stats = result['data']['attributes']['stats']
                return result['data']['attributes']
            elif status == 'queued' or status == 'in-progress':
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    continue
                else:
                    return "Analysis is still in progress. Please try again later."
        except requests.exceptions.RequestException as e:
            print(f"Error in get_analysis_result (attempt {attempt + 1}): {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response content: {e.response.content}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                return f"Error getting analysis result after {max_retries} attempts: {str(e)}"

    return "Failed to get analysis result after multiple attempts."

def generate_risk_message(stats):
    total_scans = sum(stats.values())
    malicious = stats['malicious']
    suspicious = stats['suspicious']
    
    if malicious > 0:
        risk_level = "High"
        emoji = "🚨"
    elif suspicious > 0:
        risk_level = "Medium"
        emoji = "⚠️"
    else:
        risk_level = "Low"
        emoji = "✅"
    
    potential_risks = [
        "Malware infection",
        "Phishing attempt",
        "Data theft",
        "Identity theft",
        "Financial fraud"
    ]
    
    risk_message = f"{emoji} **Risk Level: {risk_level}**\n\n"
    risk_message += f"**Scan Results:**\n"
    risk_message += f"- Malicious: {malicious}\n"
    risk_message += f"- Suspicious: {suspicious}\n"
    risk_message += f"- Clean: {stats['harmless']}\n\n"
    
    if risk_level != "Low":
        risk_message += "**Potential Risks:**\n"
        for risk in potential_risks[:3]:  # List top 3 risks
            risk_message += f"- {risk}\n"
        
        risk_message += "\n⚠️ **WARNING:** Visiting this URL may put your system and personal information at risk. Proceed with caution!"
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

    # Check for URLs in the message
    words = message.content.split()
    for word in words:
        if word.startswith(('http://', 'https://')):
            await message.channel.send(f"🔍 Scanning URL: {word}")
            result = await scan_url(word)
            
            if isinstance(result, dict):
                stats = result['stats']
                risk_message = generate_risk_message(stats)
                await message.channel.send(risk_message)
                
                # Send report to "reports" channel if the URL is malicious
                if stats['malicious'] > 0:
                    reports_channel = discord.utils.get(message.guild.channels, name='reports')
                    if reports_channel:
                        report = f"🚨 **Malicious URL Detected**\n\n"
                        report += f"User: {message.author.mention}\n"
                        report += f"Channel: {message.channel.mention}\n"
                        report += f"URL: {word}\n\n"
                        report += risk_message
                        await reports_channel.send(report)
            else:
                await message.channel.send(result)

    await bot.process_commands(message)

# Command to manually scan a URL
@bot.command(name='scan')
async def scan(ctx, url):
    await ctx.send(f"🔍 Scanning URL: {url}")
    result = await scan_url(url)
    if isinstance(result, dict):
        risk_message = generate_risk_message(result['stats'])
        await ctx.send(risk_message)
    else:
        await ctx.send(result)

# Start the Flask server
keep_alive()

# Run the bot
token = os.getenv('DISCORD_TOKEN')
if token:
    bot.run(token)
else:
    print("Error: DISCORD_TOKEN not found in environment variables")
