@rem Minimal Windows wrapper launcher; this project targets Linux x86_64 execution.
@echo off
set DIR=%~dp0
if not exist "%DIR%gradle\wrapper\gradle-wrapper.jar" (
  echo ERROR: Missing gradle\wrapper\gradle-wrapper.jar 1>&2
  exit /b 1
)
"%JAVA_HOME%\bin\java.exe" -classpath "%DIR%gradle\wrapper\gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain %*
