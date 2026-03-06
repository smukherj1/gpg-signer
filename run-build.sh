#!/bin/bash
set -e

GRADLE_VERSION="9.4.0"
GRADLE_DIR=".gradle-bin"
GRADLE_ZIP="gradle-${GRADLE_VERSION}-bin.zip"
GRADLE_URL="https://services.gradle.org/distributions/${GRADLE_ZIP}"
GRADLE_CMD="./${GRADLE_DIR}/gradle-${GRADLE_VERSION}/bin/gradle"

if [ ! -f "$GRADLE_CMD" ]; then
    echo "Downloading Gradle $GRADLE_VERSION..."
    mkdir -p "$GRADLE_DIR"
    wget -q "$GRADLE_URL" -O "${GRADLE_DIR}/${GRADLE_ZIP}"
    echo "Extracting Gradle..."
    unzip -q "${GRADLE_DIR}/${GRADLE_ZIP}" -d "$GRADLE_DIR"
    rm "${GRADLE_DIR}/${GRADLE_ZIP}"
fi

echo "Running Gradle build..."
$GRADLE_CMD installDist "$@"

echo ""
echo "Build complete. You can run the binary using:"
echo "./build/install/gpg-signer/bin/gpg-signer --help"
