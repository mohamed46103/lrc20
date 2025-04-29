# LRC20 infrastructure

This directory contains configs for setuping and building production ready
environments for LRC20 project.

## Build

To build new version of `lrc20d` docker container you need to run `docker build`
with these options from root of the repo:

```sh
docker build --no-cache -f ./infrastructure/build/lrc20d-crosscompile.Dockerfile -t lightspark/lrc20d:local-build .
```

## Setup dev environment

Start services with `docker-compose`:

```sh
# Regular setup for development with one node
docker compose --file ./infrastructure/dev/docker-compose.yaml --project-directory . up

# Setup with two LRC20 nodes
docker compose --file ./infrastructure/dev/docker-compose.yaml --project-directory . --profile two_nodes_setup up

# Setup with three LRC20 nodes
docker compose --file ./infrastructure/dev/docker-compose.yaml --project-directory . --profile three_nodes_setup up

# Setup with three LRC20 nodes, two Bitcoin nodes and two Electrs backends
docker compose --file ./infrastructure/dev/docker-compose.yaml --project-directory . --profile end_to_end up
```

There is an issue for docker compose while using both profiled and non-profiled setup, so if you would have network issues you could use `--force-recreate` flag at the end

## Regtest interactions

For regtest interactions you would need to have some bitcoin. To get some, you could mine block to your address using command 
`bitcoin-cli -regtest generatetoaddress 1 <address>` inside bitcoin node container.
