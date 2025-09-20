# intercom-cookie-helper

A simple Go HTTP server with health check endpoint.

## Quick Start

```bash
make run
```

The server will start on port 8080 (or PORT environment variable if set).

## Available Commands

```bash
make run         # Start the server
make build       # Build the server binary to bin/server
make test        # Run all tests
make fmt         # Format code with gofmt
make fmt-strict  # Format code with gofumpt and gofmt
make stop        # Stop the running server
make restart     # Stop and restart the server
```

## API Endpoints

- `GET /healthz` - Health check endpoint
  - Returns: `200 OK` with `{"status":"ok"}`

## Configuration

The server reads configuration from environment variables:

- `PORT` - Server port (default: 8080)