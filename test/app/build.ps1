# Build the throwaway ordinary-app target used by the KCLF app tests.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File test\app\build.ps1
#   ... -SdkRoot D:\androidSDK -Platform android-36 -NdkRoot D:\androidSDK\ndk\27.0.12077973
#
# Output: build\kclf-apptest\app.apk (debug signed). The app is debuggable and
# contains lib/arm64-v8a/libkclfhost.so plus libkclfapp_payload.so. Installing
# with extractNativeLibs=true places the payload in the app's linker-visible
# native library directory, which is what a normal app injection can load.
param(
    [string]$SdkRoot = '',
    [string]$NdkRoot = '',
    [string]$BuildTools = '',
    [string]$Platform = '',
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Continue'

function Fail([string]$Message) { throw $Message }
function Run([string]$Exe, [string[]]$ArgList, [string]$What) {
    & $Exe @ArgList 2>&1 | Out-Null
    $Code = $LASTEXITCODE
    if ($Code -ne 0) { Fail "$What failed (rc=$Code): $Exe" }
}

if (-not $SdkRoot) {
    if ($env:ANDROID_SDK_ROOT) { $SdkRoot = $env:ANDROID_SDK_ROOT }
    elseif ($env:ANDROID_HOME) { $SdkRoot = $env:ANDROID_HOME }
    elseif (Test-Path 'D:\androidSDK') { $SdkRoot = 'D:\androidSDK' }
    else { Fail 'Set -SdkRoot or ANDROID_HOME/ANDROID_SDK_ROOT.' }
}
if (-not (Test-Path $SdkRoot)) { Fail "Android SDK not found: $SdkRoot" }

if (-not $Platform) {
    $Platform = Get-ChildItem (Join-Path $SdkRoot 'platforms') -Directory |
        Where-Object { $_.Name -match '^android-\d+$' } |
        Sort-Object { [int]($_.Name -replace '^android-', '') } |
        Select-Object -Last 1 -ExpandProperty Name
    if (-not $Platform) { Fail "No android-* platform under $SdkRoot\platforms" }
}
$AndroidJar = Join-Path $SdkRoot "platforms\$Platform\android.jar"
if (-not (Test-Path $AndroidJar)) { Fail "android.jar not found: $AndroidJar" }

if (-not $BuildTools) {
    $BuildTools = Get-ChildItem (Join-Path $SdkRoot 'build-tools') -Directory |
        Sort-Object Name | Select-Object -Last 1 -ExpandProperty FullName
    if (-not $BuildTools) { Fail "No build-tools under $SdkRoot\build-tools" }
}
$Aapt2 = Join-Path $BuildTools 'aapt2.exe'
$D8 = Join-Path $BuildTools 'd8.bat'
$ZipAlign = Join-Path $BuildTools 'zipalign.exe'
$ApkSigner = Join-Path $BuildTools 'apksigner.bat'
foreach ($Tool in @($Aapt2, $D8, $ZipAlign, $ApkSigner)) {
    if (-not (Test-Path $Tool)) { Fail "Missing build tool: $Tool" }
}

if (-not $NdkRoot) {
    $NdkRoot = Get-ChildItem (Join-Path $SdkRoot 'ndk') -Directory |
        Sort-Object Name | Select-Object -Last 1 -ExpandProperty FullName
    if (-not $NdkRoot) { Fail "No NDK under $SdkRoot\ndk" }
}
$Clang = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android26-clang.cmd'
if (-not (Test-Path $Clang)) { Fail "NDK clang wrapper not found: $Clang" }

if (-not $OutDir) {
    $OutDir = Join-Path $PSScriptRoot '..\..\..\..\build\kclf-apptest'
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$Work = Join-Path $OutDir 'work'
Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force (Join-Path $Work 'classes'), (Join-Path $Work 'dex'), (Join-Path $Work 'obj') | Out-Null

Write-Host "SDK=$SdkRoot platform=$Platform build-tools=$BuildTools"
Write-Host "NDK=$NdkRoot"

Run 'javac' @('-source', '8', '-target', '8', '-Xlint:-options', '-classpath', $AndroidJar,
    '-d', (Join-Path $Work 'classes'), (Join-Path $PSScriptRoot 'src\com\kclf\apptest\MainActivity.java')) 'javac'
$ClassFiles = @(Get-ChildItem (Join-Path $Work 'classes') -Recurse -Filter *.class | ForEach-Object FullName)
Run $D8 (@('--lib', $AndroidJar, '--min-api', '26', '--output', (Join-Path $Work 'dex')) + $ClassFiles) 'd8'

Run $Clang @('-Wall', '-Wextra', '-Werror', '-O2', '-shared', '-fPIC',
    (Join-Path $PSScriptRoot 'jni\host.c'), '-o', (Join-Path $Work 'obj\libkclfhost.so')) 'host clang'
Run $Clang @('-Wall', '-Wextra', '-Werror', '-O2', '-shared', '-fPIC',
    (Join-Path $PSScriptRoot 'jni\payload.c'), '-o', (Join-Path $Work 'obj\libkclfapp_payload.so')) 'payload clang'

$KeyStore = Join-Path $Work 'debug.keystore'
Run 'keytool' @('-genkeypair', '-keystore', $KeyStore, '-storepass', 'android', '-keypass', 'android',
    '-alias', 'androiddebugkey', '-dname', 'CN=Android Debug,O=Android,C=US',
    '-keyalg', 'RSA', '-validity', '10000') 'keytool'

$BaseApk = Join-Path $Work 'base.apk'
$AlignedApk = Join-Path $Work 'aligned.apk'
$FinalApk = Join-Path $OutDir 'app.apk'
Remove-Item -Force $BaseApk, $AlignedApk, $FinalApk -ErrorAction SilentlyContinue
Run $Aapt2 @('link', '--manifest', (Join-Path $PSScriptRoot 'AndroidManifest.xml'),
    '-I', $AndroidJar, '--min-sdk-version', '26', '--target-sdk-version', '35',
    '-o', $BaseApk) 'aapt2 link'

Add-Type -AssemblyName System.IO.Compression.FileSystem
$Zip = [System.IO.Compression.ZipFile]::Open($BaseApk, 'Update')
try {
    foreach ($Pair in @(
        @('classes.dex', (Join-Path $Work 'dex\classes.dex')),
        @('lib/arm64-v8a/libkclfhost.so', (Join-Path $Work 'obj\libkclfhost.so')),
        @('lib/arm64-v8a/libkclfapp_payload.so', (Join-Path $Work 'obj\libkclfapp_payload.so')))) {
        $Entry = $Zip.CreateEntry($Pair[0], [System.IO.Compression.CompressionLevel]::Optimal)
        $In = [System.IO.File]::OpenRead($Pair[1])
        try {
            $Out = $Entry.Open()
            $In.CopyTo($Out)
            $Out.Dispose()
        } finally { $In.Dispose() }
    }
} finally { $Zip.Dispose() }

Run $ZipAlign @('-f', '4', $BaseApk, $AlignedApk) 'zipalign'
Run $ApkSigner @('sign', '--ks', $KeyStore, '--ks-pass', 'pass:android', '--key-pass', 'pass:android',
    '--out', $FinalApk, $AlignedApk) 'apksigner'
Write-Host "built $FinalApk"
