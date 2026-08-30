# Write bytes to a path on the remote host.
#
# The content arrives as a bound byte[] parameter, so there is no base64
# staging file and no chunked upload -- one pipeline, one write.
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Content
)

$ErrorActionPreference = 'Stop'

[IO.File]::WriteAllBytes($Path, $Content)
