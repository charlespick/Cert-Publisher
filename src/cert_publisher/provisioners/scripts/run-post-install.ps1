# Run the operator-supplied post-install hook.
#
# The script text arrives as a bound string parameter and is written to a
# temp .ps1 so operators can keep using $MyInvocation, param blocks and
# multi-statement scripts unchanged. It is written with a UTF-8 BOM because
# Windows PowerShell reads BOM-less .ps1 files as ANSI, which would mangle
# any non-ASCII text in the hook.
#
# The just-installed leaf's thumbprint is exposed as
# $env:CERT_PUBLISHER_THUMBPRINT -- 40 uppercase hex characters, no colons or
# spaces, matching Windows' own Cert:\ formatting and the literal form most
# .NET-based tooling (e.g. Veeam) expects.
param(
    [Parameter(Mandatory = $true)][string]$Script,
    [Parameter(Mandatory = $true)][string]$Thumbprint
)

$ErrorActionPreference = 'Stop'

$hook = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName() + '.ps1')
try {
    [IO.File]::WriteAllText($hook, $Script, [Text.UTF8Encoding]::new($true))
    $env:CERT_PUBLISHER_THUMBPRINT = $Thumbprint
    $global:LASTEXITCODE = 0
    & $hook
    if ($LASTEXITCODE -ne 0) {
        throw "post-install script exited $LASTEXITCODE"
    }
} finally {
    Remove-Item -LiteralPath $hook -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'Env:\CERT_PUBLISHER_THUMBPRINT' -Force -ErrorAction SilentlyContinue
}
