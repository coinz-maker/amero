.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/amero/go-amero/cmd/swarm
	go build -o bin/geth     github.com/amero/go-amero/cmd/geth
	go build -o bin/bootnode github.com/amero/go-amero/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/amero/go-amero/swarm/...
