import os
from dotenv import load_dotenv
import discord
from discord.ext import commands
import requests
import asyncio
from flask import Flask
from threading import Thread
import json
import time  # Import time module

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

# Define check_rate_limit function
async def check_rate_limit():
    global request_times
    
    # Get the current time
    current_time = time.time()
    
    # Filter out requests that are older than 60 seconds (1 minute)
    request_times = [t for t in request_times if current_time - t < 60]
    
    # If the number of requests in the last minute exceeds the max allowed, wait
    if len(request_times) >= MAX_REQUESTS_PER_MINUTE:
        sleep_time = 60 - (current_time - request_times[0])
        print(f"Rate limit exceeded. Sleeping for {sleep_time:.2f} seconds.")
        await asyncio.sleep(sleep_time)
    
    # Add the current time to the list of request times
    request_times.append(current_time)

async def scan_url(url):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    data = {"url": url}
    
    try:
        response = requests.post(VIRUSTOTAL_API_URL, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        analysis_id = result['data']['id']
        return await get_analysis_result(analysis_id)
    except requests.exceptions.RequestException as e:
        return f"Error scanning URL: {str(e)}"

async def get_analysis_result(analysis_id):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(f"{VIRUSTOTAL_API_URL}/{analysis_id}", headers=headers)
        response.raise_for_status()
        result = response.json()
        stats = result['data']['attributes']['stats']
        return f"Scan results: Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Harmless: {stats['harmless']}"
    except requests.exceptions.RequestException as e:
        return f"Error getting analysis result: {str(e)}"

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

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
