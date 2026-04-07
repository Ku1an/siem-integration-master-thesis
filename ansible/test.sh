#!/bin/bash

images=$(docker images --format "{{.Repository}}:{{.Tag}}")


if [ -z "$images" ]; then
  echo "No docker images found. Exists..."
  exit 0
fi


for image in $images; do
    trivy image $image
done



