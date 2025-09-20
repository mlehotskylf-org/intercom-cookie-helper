# Builder stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with CGO disabled for static binary
ENV CGO_ENABLED=0
RUN go build -o /server ./cmd/server

# Final stage
FROM gcr.io/distroless/static:nonroot

# Copy binary from builder
COPY --from=builder /server /server

# Set user
USER nonroot:nonroot

# Expose port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["/server"]