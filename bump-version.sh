#!/bin/bash

VERSION=$1
CURRENT_VERSION=$(git tag | grep ^v[0-9] | sort -V | tail -1)

if [[  -z "${VERSION}" ]]; then
    VERSION="${CURRENT_VERSION%.*}.$((${CURRENT_VERSION/*./} + 1))"
    echo "New version is: ${VERSION}"
fi

if [[ ! $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "VERSION must be a semantic version: vMAJOR.MINOR.PATCH"
    exit 1
fi

if [[ 'main' != "$(git branch --show-current)" ]]; then
    echo "Not on main git branch!"
    exit 1
fi

if [[ -n "$(git tag -l $VERSION)" ]]; then
    echo "VERSION $VERSION already exists!"
    exit 1
fi

if [[ $VERSION != `(echo $VERSION; git tag | grep ^v[0-9]) | sort -V | tail -1` ]]; then
    echo "$VERSION is not semantically newest!"
    exit 1
fi

if [[ -n "$(git status --porcelain | grep -v '^?? ')" ]]; then
    echo "Cannot set version when working directory has differences"
fi

sed -i "s/^version: .*/version: ${VERSION:1}/" helm/Chart.yaml
sed -i "s/^appVersion: .*/appVersion: ${VERSION:1}/" helm/Chart.yaml

git add helm/Chart.yaml
git commit -m "Release $VERSION"
git tag $VERSION
git push origin main $VERSION
