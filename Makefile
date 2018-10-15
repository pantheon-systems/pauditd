bin:
	dep ensure
	GOOS=linux GOARCH=amd64 go build

test:
	dep ensure
	go test $$(go list ./...)

test-cov-html:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=.

bench-cpu:
	go test -bench=. -benchtime=5s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

bench-cpu-long:
	go test -bench=. -benchtime=60s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

.PHONY: test test-cov-html bench bench-cpu bench-cpu-long bin
.DEFAULT_GOAL := bin
