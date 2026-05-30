#!/bin/sh
# Minimal Gradle wrapper launcher; requires gradle/wrapper/gradle-wrapper.jar.
APP_HOME=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || exit 1
CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
if [ ! -f "$CLASSPATH" ]; then
  echo "ERROR: Missing $CLASSPATH" >&2
  echo "Run 'gradle wrapper --gradle-version 8.14.3' once with a local Gradle install, or add the standard wrapper JAR." >&2
  exit 1
fi
exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -classpath "$CLASSPATH" org.gradle.wrapper.GradleWrapperMain "$@"
