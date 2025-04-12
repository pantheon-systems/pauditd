FROM golang:1.24-alpine

# Install essential packages
RUN apk add --no-cache \
    bash \
    git \
    make \
    curl \
    grep \
    coreutils \
    gcc \
    g++ \
    musl-dev \
    libc6-compat

# Optional: Install golangci-lint (static binary)
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin v2.0.2

# Optional: Install go-ctrf-json-reporter
RUN go install github.com/ctrf-io/go-ctrf-json-reporter/cmd/go-ctrf-json-reporter@latest

# Optional: Install goreleaser (static binary)
RUN curl -sSfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh -s -- -b /usr/local/bin

# Set up working directory
WORKDIR /workspace

# Default command
CMD ["sh"]