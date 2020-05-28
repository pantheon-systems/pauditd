APP:=pauditd

ifndef CIRCLECI
  BUILD_NUM := dev-$(shell git rev-parse --short HEAD)
endif
ifndef BUILD_NUM
  BUILD_NUM := dev
endif

ifdef CIRCLE_BUILD_NUM
  BUILD_NUM := $(CIRCLE_BUILD_NUM)
  QUAY := docker login -p "$$QUAY_PASSWD" -u "$$QUAY_USER" quay.io
endif

# These can be overridden
REGISTRY ?= quay.io/getpantheon
IMAGE		 ?= $(REGISTRY)/$(APP):$(BUILD_NUM)

build: build-linux

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build

test:
	go test $$(go list ./...) -race

test-cov-html:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=.

bench-cpu:
	go test -bench=. -benchtime=5s -cpuprofile=cpu.pprof
	go tool pprof pauditd.test cpu.pprof

bench-cpu-long:
	go test -bench=. -benchtime=60s -cpuprofile=cpu.pprof
	go tool pprof pauditd.test cpu.pprof

build-docker:
	docker build -t $(IMAGE) .

push-circle: setup-quay
	make push

push:
	docker push $(IMAGE)

snapshot:
	goreleaser --snapshot --rm-dist --debug

setup-quay:: ## setup docker login for quay.io
ifdef CIRCLE_BUILD_NUM
	@$(QUAY) > /dev/null
endif

.PHONY: test test-cov-html bench bench-cpu bench-cpu-long bin setup-quay build-docker push push-circle
