#!/bin/bash
echo "Starting APEX Security Scanner Platform..."
# Start all services detached, force build, force recreate containers, and renew anonymous volumes (fixes frontend cache)
docker compose up -d --build --force-recreate -V
echo "
APEX Platform is running!
- Frontend: http://localhost:5173
- Backend:  http://localhost:8000
- Database: Running on port 3306
"
