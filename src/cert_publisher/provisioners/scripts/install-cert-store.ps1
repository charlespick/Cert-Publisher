# Import a PKCS#12 blob into a Windows certificate store, entirely in memory.
#
# The PFX arrives as a bound byte[] parameter and its password as a bound
# SecureString, so neither ever appears on a command line, in process-creation
# telemetry, or in the WSMan operational log. Nothing is written to disk:
# PFXImportCertStore takes the bytes directly, where Import-PfxCertificate
# requires a file path.
#
# This calls PFXImportCertStore itself rather than going through
# X509Certificate2Collection.Import: on Windows PowerShell 5.1 (.NET Framework)
# that API can't select a key provider, and lands the key in the legacy CAPI
# "Microsoft Enhanced Cryptographic Provider v1.0". AD DS served LDAPS from a
# key imported that way with a handshake signature that didn't verify against
# its own certificate, while certutil -verifystore reported it healthy.
# PKCS12_ALWAYS_CNG_KSP puts the key in the Microsoft Software Key Storage
# Provider, where Import-PfxCertificate (and the pre-PSRP transport) put it.
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

# A pooled runspace can run this script more than once; Add-Type throws if the
# type already exists in the session.
if (-not ('CertPublisher.Pfx' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CertPublisher {
    public static class Pfx {
        public const uint CRYPT_EXPORTABLE = 0x00000001;
        public const uint CRYPT_MACHINE_KEYSET = 0x00000020;
        public const uint CRYPT_USER_KEYSET = 0x00001000;
        public const uint PKCS12_ALWAYS_CNG_KSP = 0x00000200;

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_DATA_BLOB {
            public uint cbData;
            public IntPtr pbData;
        }

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr PFXImportCertStore(
            ref CRYPT_DATA_BLOB pPFX, IntPtr szPassword, uint dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertEnumCertificatesInStore(
            IntPtr hCertStore, IntPtr pPrevCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        // szPassword is a NUL-terminated UTF-16 string the caller owns, so the
        // plaintext only ever lives in unmanaged memory it can zero.
        public static IntPtr Import(byte[] pfx, IntPtr szPassword, uint flags) {
            GCHandle pin = GCHandle.Alloc(pfx, GCHandleType.Pinned);
            try {
                CRYPT_DATA_BLOB blob;
                blob.cbData = (uint)pfx.Length;
                blob.pbData = pin.AddrOfPinnedObject();
                IntPtr store = PFXImportCertStore(ref blob, szPassword, flags);
                if (store == IntPtr.Zero) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return store;
            } finally {
                pin.Free();
            }
        }
    }
}
'@
}

$location = [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation

$flags = [CertPublisher.Pfx]::PKCS12_ALWAYS_CNG_KSP
if ($location -eq [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine) {
    $flags = $flags -bor [CertPublisher.Pfx]::CRYPT_MACHINE_KEYSET
} else {
    $flags = $flags -bor [CertPublisher.Pfx]::CRYPT_USER_KEYSET
}
if ($Exportable) {
    $flags = $flags -bor [CertPublisher.Pfx]::CRYPT_EXPORTABLE
}

$passwordPtr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Password)
try {
    $pfxStore = [CertPublisher.Pfx]::Import($PfxBytes, $passwordPtr, [uint32]$flags)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($passwordPtr)
}

# The key is persisted by the import itself; the store PFXImportCertStore
# returns is in-memory and only carries the certificates bound to it.
$certs = [Collections.Generic.List[Security.Cryptography.X509Certificates.X509Certificate2]]::new()
try {
    $ctx = [IntPtr]::Zero
    while (($ctx = [CertPublisher.Pfx]::CertEnumCertificatesInStore($pfxStore, $ctx)) -ne [IntPtr]::Zero) {
        # Duplicates the context, so it outlives the enumeration and the store.
        $certs.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($ctx))
    }

    $store = [Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $location)
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        foreach ($cert in $certs) {
            $store.Add($cert)
        }
    } finally {
        $store.Close()
    }
} finally {
    foreach ($cert in $certs) {
        $cert.Dispose()
    }
    [void][CertPublisher.Pfx]::CertCloseStore($pfxStore, 0)
}
