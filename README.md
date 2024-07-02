# ChainKeeper Bot

ChainKeeper Bot is a Telegram bot that helps you keep track of your bicycle chain maintenance by integrating with Strava. It monitors the distance you've traveled and reminds you when it's time to clean or lube your chain.

I would like to host the bot for everyone, but Strava has a limit on the number of athletes for developer applications. I have requested an extension for this limit but have not received a response yet.

## Features

- Connects to your Strava account to fetch activity data.
- Tracks when you last cleaned and lubed your chain.
- Sends reminders when it's time to clean or lube your chain based on distance traveled.
- Allows you to update maintenance intervals and reset maintenance counters.

## Setup

### Prerequisites

- Docker
- Docker Compose
- A Telegram bot token (you can obtain one from [BotFather](https://t.me/BotFather))
- A MongoDB instance (you can use [MongoDB Atlas](https://www.mongodb.com/products/platform/atlas-database) free tier or a local instance)
- Strava API credentials (Client ID and Client Secret from [StravaDevelopers](https://developers.strava.com/))
- Domain with HTTPS (you can use [sslip.io](https://sslip.io/))

### Environment Variables

Create a `.env` file in the root of the project with the following environment variables:
```
TELEGRAM_BOT_TOKEN=<your_telegram_bot_token>
MONGODB_URI=<your_mongodb_uri>
STRAVA_CLIENT_ID=<your_strava_client_id>
STRAVA_CLIENT_SECRET=<your_strava_client_secret>
STRAVA_AUTH_URL=https://www.strava.com/oauth/authorize
STRAVA_REDIRECT_URI=https://<domain_with_ssl>/auth/strava/callback
PORT=8080
```
### Usage

1. Start docker compose `docker-compose up -d`
1. Start a chat with the bot on Telegram.
2. Use the `/start` command to begin.
3. Follow the instructions to connect your Strava account and set the intervals for cleaning and lubing your chain.
4. The bot will track your activities and remind you when it's time to clean or lube your chain.

### Notes

- The service is provided as is without any warranties. The author is not responsible for any issues arising from the use of this service.
- The bot uses the Strava API to fetch activity data.
- Feel free to contact the author on Telegram: [@iceflame](https://t.me/iceflame)
