# Intern Project

The intern just finished this shiny gateway and proudly said:
"I think it’s secure!… maybe you should double-check?"

## Quick start
- Using Docker Compose (recommended)
    - From the project root:
        - docker-compose up --build
    - Inspect docker-compose.yml for the exposed port and access the service in your browser.

## What to inspect
- server.js — primary backend logic and request handling
- public/index.html — frontend entrypoint
- public/assets/ui.js — client-side behavior and API calls
- package.json, Dockerfile, docker-compose.yml — run configuration and environment
