import os
from dotenv import load_dotenv
import discord
from discord.ext import commands
import requests
import asyncio
from flask import Flask
from threading import Thread

# Load environment variables
load_dotenv()  # This will load variables from .env file if it exists

# Debug: Print environment variables
print("Environment Variables:")
print(f"DISCORD_TOKEN: {os.getenv('DISCORD_TOKEN')}")
print(f"VIRUSTOTAL_API_KEY: {os.getenv('VIRUSTOTAL_API_KEY')}")

# Bot setup
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
    global request_times
    current_time = asyncio.get_event_loop().time()
    request_times = [t for t in request_times if current_time - t < 60]
    if len(request_times) >= MAX_REQUESTS_PER_MINUTE:
        wait_time = 60 - (current_time - request_times[0])
        await asyncio.sleep(wait_time)
    request_times.append(current_time)

async def scan_url(url):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    data = {"url": url}
    response = requests.post(VIRUSTOTAL_API_URL, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        return await get_analysis_result(analysis_id)
    else:
        return f"Error scanning URL: {response.status_code}"

async def get_analysis_result(analysis_id):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(f"{VIRUSTOTAL_API_URL}/{analysis_id}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        stats = result['data']['attributes']['stats']
        return f"Scan results: Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Harmless: {stats['harmless']}"
    else:
        return f"Error getting analysis result: {response.status_code}"

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
            await message.channel.send(f"Scanning URL: {word}")
            result = await scan_url(word)
            await message.channel.send(result)

    await bot.process_commands(message)

# Command to manually scan a URL
@bot.command(name='scan')
async def scan(ctx, url):
    await ctx.send(f"Scanning URL: {url}")
    result = await scan_url(url)
    await ctx.send(result)

# Start the Flask server
keep_alive()

# Run the bot
token = os.getenv('DISCORD_TOKEN')
if token:
    bot.run(token)
else:
    print("Error: DISCORD_TOKEN not found in environment variables")
