FROM golang:1.24-alpine

# Install Air for hot reload (compatible with Go 1.24)
RUN go install github.com/air-verse/air@v1.61.1

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy Air configuration
COPY .air.toml ./

# Copy source code
COPY . .

# Default command runs Air for development hot reload
CMD ["air"]