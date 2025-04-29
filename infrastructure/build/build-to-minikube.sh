#!/bin/bash

eval "$(minikube docker-env)"
echo "Building images in minikube's docker environment..."

echo "Building yuvd (lrc20d) image..."
script_dir=$(dirname "$0")
repo_root=$(git rev-parse --show-toplevel)
docker build -t yuvd:dev -f "$script_dir"/lrc20d-crosscompile.Dockerfile "$repo_root"
echo "Successfully built yuvd:dev (lrc20d)"

echo -e "\nAvailable images in minikube:"
docker images | grep -E "^(yuvd)\s+"

echo -e "\nNote: To interact with these images in your terminal, run:"
echo "  eval \$(minikube docker-env)"
echo "To revert back to your local docker:"
echo "  eval \$(minikube docker-env -u)"
