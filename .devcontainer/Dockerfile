FROM golang:1.24-alpine

# Install essential packages
RUN apk add --no-cache \
    bash \
    bash-completion \
    git \
    make \
    curl \
    grep \
    coreutils \
    gcc \
    g++ \
    musl-dev \
    libc6-compat \
    yq \
    jq

# Set up Go environment
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH
ENV GO111MODULE=on

# Install golangci-lint (static binary)
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin v2.0.2

# Install formatters and tools
RUN go install github.com/daixiang0/gci@latest && \
    go install mvdan.cc/gofumpt@latest && \
    go install golang.org/x/tools/cmd/goimports@latest && \
    go install github.com/ctrf-io/go-ctrf-json-reporter/cmd/go-ctrf-json-reporter@latest

# Optional: Install goreleaser (static binary)
RUN curl -sSfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh -s -- -b /usr/local/bin

# Copy the helper script into the container
COPY run-linter /usr/local/bin/run-linter
RUN chmod +x /usr/local/bin/run-linter

# Copy the shell configuration file into the container
COPY devcontainer-bashrc /root/.bashrc

# Set up working directory
WORKDIR /workspace

# Default command
CMD ["bash"]