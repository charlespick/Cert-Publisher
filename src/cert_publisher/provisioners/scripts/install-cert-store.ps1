# Import a PKCS#12 blob into a Windows certificate store, entirely in memory.
#
# The PFX arrives as a bound byte[] parameter and its password as a bound
# SecureString, so neither ever appears on a command line, in process-creation
# telemetry, or in the WSMan operational log. Nothing is written to disk: the
# X509Certificate2Collection is built from the bytes directly rather than via
# Import-PfxCertificate, which requires a file path.
#
# Every certificate in the blob is added, matching what Import-PfxCertificate
# does -- the leaf carries the private key, the rest are the issuing chain.
param(
    [Parameter(Mandatory = $true)][byte[]]$PfxBytes,
    [Parameter(Mandatory = $true)][securestring]$Password,
    [Parameter(Mandatory = $true)][string]$StoreLocation,
    [Parameter(Mandatory = $true)][string]$StoreName,
    [bool]$Exportable = $false
)

$ErrorActionPreference = 'Stop'

$location = [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation

$flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
if ($location -eq [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine) {
    $flags = $flags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
} else {
    $flags = $flags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
}
if ($Exportable) {
    $flags = $flags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
}

$collection = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$collection.Import($PfxBytes, $Password, $flags)
try {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $location)
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        foreach ($cert in $collection) {
            $store.Add($cert)
        }
    } finally {
        $store.Close()
    }
} finally {
    foreach ($cert in $collection) {
        $cert.Dispose()
    }
}
