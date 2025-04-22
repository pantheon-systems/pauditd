# Build for linux/amd64 regardless of the host system architecture.
# Install qemu to emulate amd64 inside the container for ARM64 hosts.
FROM --platform=linux/amd64 golang:1.24-bookworm

# Install essential packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    bash-completion \
    git \
    make \
    curl \
    grep \
    coreutils \
    gcc \
    g++ \
    libc6-dev \
    jq \
    yq \
    qemu-user-static \
    docker.io \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

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

# Install goreleaser (static binary)
ENV GORELEASER_VERSION=2.8.2
RUN curl -sSfL https://github.com/goreleaser/goreleaser/releases/download/v${GORELEASER_VERSION}/goreleaser_Linux_x86_64.tar.gz \
    | tar -xz -C /usr/local/bin goreleaser

# Copy the helper script into the container
COPY run-linter /usr/local/bin/run-linter
RUN chmod +x /usr/local/bin/run-linter

# Copy the shell configuration file into the container
COPY devcontainer-bashrc /root/.bashrc

# Set up working directory
WORKDIR /workspaces

# Default command
CMD ["bash"]