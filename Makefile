OUT := $(shell pwd)

build:
	go get ./...
	go build -C server -o "${OUT}/out/"

docker: build
	docker build -t quay.io/jewertow/trust-bundle-sds:latest .
