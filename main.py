import os
from dotenv import load_dotenv
import discord
from discord.ext import commands
import requests
import asyncio
from flask import Flask
from threading import Thread
import json

# Load environment variables
load_dotenv()  # This will load variables from .env file if it exists

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

async def scan_url(url):
    await check_rate_limit()
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    data = {"url": url}
    print(f"Sending POST request to {VIRUSTOTAL_API_URL}")
    print(f"Headers: {json.dumps(headers, indent=2)}")
    print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(VIRUSTOTAL_API_URL, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        print(f"Response: {json.dumps(result, indent=2)}")
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
    url = f"{VIRUSTOTAL_API_URL}/{analysis_id}"
    print(f"Sending GET request to {url}")
    print(f"Headers: {json.dumps(headers, indent=2)}")
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        print(f"Response: {json.dumps(result, indent=2)}")
        stats = result['data']['attributes']['stats']
        return f"Scan results: Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Harmless: {stats['harmless']}"
    except requests.exceptions.RequestException as e:
        print(f"Error in get_analysis_result: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.content}")
        return f"Error getting analysis result: {str(e)}"


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
