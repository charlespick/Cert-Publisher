# Report whether a certificate is present in a Windows certificate store and,
# if so, whether its private key is exportable.
#
# Exportability can't be read reliably via CspKeyContainerInfo (it throws for
# CNG-backed keys, which is what modern Windows uses by default), so this
# probes the only way that works across both CAPI and CNG: attempt an
# in-memory PKCS#12 export and see if it's refused. The exported bytes never
# leave the remote process or touch disk.
#
# Writes exactly one of: absent, present:nokey, present:sealed,
# present:exportable.
param(
    [Parameter(Mandatory = $true)][string]$StoreLocation,
    [Parameter(Mandatory = $true)][string]$StoreName,
    [Parameter(Mandatory = $true)][string]$Thumbprint
)

$ErrorActionPreference = 'Stop'

$location = [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation
$store = [Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $location)
$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
try {
    $found = $store.Certificates.Find(
        [Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $Thumbprint,
        $false)
    if ($found.Count -eq 0) {
        $result = 'absent'
    } elseif (-not $found[0].HasPrivateKey) {
        $result = 'present:nokey'
    } else {
        $result = 'present:sealed'
        try {
            [void]$found[0].Export(
                [Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12,
                'cert-publisher-probe')
            $result = 'present:exportable'
        } catch {
            # Export refused: the key was imported non-exportable.
        }
    }
} finally {
    $store.Close()
}

$result
