# Multi-stage build for efficient Go binary
# Stage 1: Builder
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
# CGO_ENABLED=0 for static binary (modernc.org/sqlite is pure Go)
# -ldflags for smaller binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o gproject cmd/web/main.go

# Stage 2: Runtime
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S gproject && \
    adduser -u 1001 -S gproject -G gproject

# Create necessary directories with proper permissions
RUN mkdir -p /app/data /app/web/templates && \
    chown -R gproject:gproject /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=gproject:gproject /app/gproject .

# Copy templates - using embedded templates so this is for reference
COPY --from=builder --chown=gproject:gproject /app/cmd/web/templates ./web/templates

# Create volume mount point for database
VOLUME ["/app/data"]

# Switch to non-root user
USER gproject

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the binary
ENTRYPOINT ["./gproject"]