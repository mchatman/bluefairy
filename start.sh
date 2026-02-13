#!/bin/sh

# Run migrations
echo "Running database migrations..."
migrate -path migrations -database "$DATABASE_URL" up

# Start the application
echo "Starting bluefairy..."
exec ./bluefairy