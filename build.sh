rm -rf ./kustomize
mkdir ./kustomize
cp deployment.yaml kustomize/
sed -i "s/BUILD_TIME/$(date +"%Y%m%d_%H%M%S")/g" kustomize/deployment.yaml

go build