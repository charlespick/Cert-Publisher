# Read a file from the remote host as base64, or write nothing if it is absent.
#
# Base64 keeps the result a single string output object; returning the raw
# byte[] would unroll into one PSRP output object per byte.
param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $Path -PathType Leaf) {
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))
}
