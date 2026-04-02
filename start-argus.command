#!/bin/bash

# Get the directory where this script lives
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting ARGUS..."
echo ""

# Start backend in background
cd "$DIR/backend"
npm run dev &
BACKEND_PID=$!

# Give backend a moment to start
sleep 2

# Start frontend in background
cd "$DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "ARGUS is starting up..."
echo "Open http://localhost:5173 in your browser in a few seconds."
echo ""
echo "Press Ctrl+C to stop both servers."
echo ""

# When this script is killed, kill both servers
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'ARGUS stopped.'" EXIT

# Wait here until Ctrl+C
wait
