using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CmdSpy.Core.Models;
using Microsoft.Win32.SafeHandles;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Checks who signed an executable and whether the signature still holds,
/// using Windows' own Authenticode verification (WinVerifyTrust) for both
/// embedded signatures and Windows catalog signatures — most of System32,
/// including cmd.exe, is catalog-signed. Also records SHA-256, size and version
/// info. Results are cached per file (path + size + timestamp).
/// </summary>
public sealed class SignatureVerifier
{
    private readonly ConcurrentDictionary<string, (long Size, DateTime Written, SignatureInfo Info)> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public bool ComputeHashes { get; init; } = true;

    /// <summary>Files larger than this are verified but not read end-to-end for SHA-256.</summary>
    public long MaxHashFileBytes { get; init; } = 64L * 1024 * 1024;

    /// <summary>Maximum path/version results retained between verification calls.</summary>
    public int MaxCacheEntries { get; init; } = 4_096;

    /// <summary>Verifies <paramref name="path"/>; the result is a copy carrying the given role/PID.</summary>
    public SignatureInfo Verify(string path, string role, int? processId = null, long maxHashBytes = long.MaxValue)
    {
        var info = VerifyCached(path, Math.Max(0, maxHashBytes));
        var copy = Clone(info);
        copy.Role = role;
        copy.ProcessId = processId;
        return copy;
    }

    /// <summary>Company and product names from a file's version resource.</summary>
    public static (string? Company, string? Product, string? Description) ReadVersionInfo(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return (null, null, null);
        try
        {
            if (!File.Exists(path)) return (null, null, null);
            var v = FileVersionInfo.GetVersionInfo(path);
            return (Clean(v.CompanyName), Clean(v.ProductName), Clean(v.FileDescription));
        }
        catch
        {
            return (null, null, null);
        }
    }

    private SignatureInfo VerifyCached(string path, long maxHashBytes)
    {
        long size = -1;
        DateTime written = default;
        try
        {
            var fi = new FileInfo(path);
            if (fi.Exists)
            {
                size = fi.Length;
                written = fi.LastWriteTimeUtc;
            }
        }
        catch
        {
        }

        if (_cache.TryGetValue(path, out var cached) && cached.Size == size && cached.Written == written)
        {
            bool hashRequired = ComputeHashes && size >= 0 &&
                size <= Math.Max(0, MaxHashFileBytes) && size <= maxHashBytes;
            if (!hashRequired || cached.Info.Sha256 is not null) return cached.Info;
        }

        var info = VerifyUncached(path, size, maxHashBytes);
        if (_cache.Count >= Math.Max(1, MaxCacheEntries)) _cache.Clear();
        _cache[path] = (size, written, info);
        return info;
    }

    private SignatureInfo VerifyUncached(string path, long size, long maxHashBytes)
    {
        var info = new SignatureInfo { Path = path };
        if (size < 0 || !File.Exists(path))
        {
            info.Status = SignatureStatus.NotFound;
            info.Detail = "The file no longer exists or is not accessible.";
            return info;
        }
        info.FileSize = size;

        try
        {
            var v = FileVersionInfo.GetVersionInfo(path);
            info.CompanyName = Clean(v.CompanyName);
            info.ProductName = Clean(v.ProductName);
            info.FileDescription = Clean(v.FileDescription);
            info.FileVersion = Clean(v.FileVersion);
            info.OriginalFileName = Clean(v.OriginalFilename);
        }
        catch
        {
        }

        if (ComputeHashes && size <= Math.Max(0, MaxHashFileBytes) && size <= maxHashBytes)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                info.Sha256 = Convert.ToHexString(SHA256.HashData(fs));
            }
            catch (Exception ex)
            {
                info.Detail = $"Could not hash the file: {ex.Message}";
            }
        }
        else if (ComputeHashes)
        {
            info.Detail = "SHA-256 skipped because the file exceeds a hashing budget.";
        }

        if (!OperatingSystem.IsWindows())
        {
            info.Status = SignatureStatus.Unavailable;
            info.Detail = "Signature checks need Windows.";
            return info;
        }

        try
        {
            int rc = WinTrust.VerifyEmbedded(path);
            if (rc == 0)
            {
                info.Status = SignatureStatus.Valid;
                info.Kind = "Embedded";
                ReadSigner(info, path);
                return info;
            }

            if (rc is WinTrust.TRUST_E_NOSIGNATURE or WinTrust.TRUST_E_SUBJECT_FORM_UNKNOWN or WinTrust.TRUST_E_PROVIDER_UNKNOWN)
            {
                var (catalogRc, catalog) = WinTrust.VerifyCatalog(path);
                if (catalog is not null)
                {
                    info.Kind = "Catalog";
                    info.Status = catalogRc == 0 ? SignatureStatus.Valid : Classify(catalogRc);
                    if (catalogRc != 0) info.Detail = Describe(catalogRc);
                    ReadSigner(info, catalog);
                    return info;
                }
                info.Status = SignatureStatus.Unsigned;
                info.Detail = "No embedded signature and not listed in any Windows catalog.";
                return info;
            }

            info.Kind = "Embedded";
            info.Status = Classify(rc);
            info.Detail = Describe(rc);
            ReadSigner(info, path);
            return info;
        }
        catch (Exception ex)
        {
            info.Status = SignatureStatus.Error;
            info.Detail = ex.Message;
            return info;
        }
    }

    private static string Classify(int rc) => rc switch
    {
        WinTrust.TRUST_E_BAD_DIGEST => SignatureStatus.Invalid,
        WinTrust.TRUST_E_CERT_SIGNATURE => SignatureStatus.Invalid,
        WinTrust.CRYPT_E_BAD_MSG => SignatureStatus.Invalid,
        WinTrust.TRUST_E_EXPLICIT_DISTRUST or WinTrust.CERT_E_UNTRUSTEDROOT or WinTrust.CERT_E_CHAINING or
        WinTrust.CERT_E_REVOKED or WinTrust.CERT_E_EXPIRED or WinTrust.CERT_E_UNTRUSTEDTESTROOT or
        WinTrust.TRUST_E_SUBJECT_NOT_TRUSTED or WinTrust.CRYPT_E_SECURITY_SETTINGS or WinTrust.CERT_E_WRONG_USAGE
            => SignatureStatus.Untrusted,
        _ => SignatureStatus.Error
    };

    private static string Describe(int rc) => rc switch
    {
        WinTrust.TRUST_E_BAD_DIGEST => "The file's contents don't match its signature (modified after signing).",
        WinTrust.TRUST_E_CERT_SIGNATURE => "The certificate's signature is not valid.",
        WinTrust.CRYPT_E_BAD_MSG => "The signature data is malformed.",
        WinTrust.TRUST_E_EXPLICIT_DISTRUST => "The signing certificate is explicitly distrusted.",
        WinTrust.CERT_E_UNTRUSTEDROOT => "The certificate chain ends in an untrusted root (e.g. self-signed).",
        WinTrust.CERT_E_CHAINING => "The certificate chain could not be built.",
        WinTrust.CERT_E_REVOKED => "The signing certificate has been revoked.",
        WinTrust.CERT_E_EXPIRED => "The signing certificate expired and the signature has no timestamp.",
        WinTrust.CERT_E_UNTRUSTEDTESTROOT => "Signed with a test certificate.",
        WinTrust.TRUST_E_SUBJECT_NOT_TRUSTED => "The subject is not trusted for the requested action.",
        WinTrust.CRYPT_E_SECURITY_SETTINGS => "Blocked by local security policy.",
        WinTrust.CERT_E_WRONG_USAGE => "The certificate is not valid for code signing.",
        _ => $"WinVerifyTrust returned 0x{rc:X8}."
    };

    private static void ReadSigner(SignatureInfo info, string signedFile)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
#pragma warning restore SYSLIB0057
            info.Publisher = Clean(cert.GetNameInfo(X509NameType.SimpleName, false));
            info.Issuer = Clean(cert.GetNameInfo(X509NameType.SimpleName, true));
            info.Thumbprint = cert.Thumbprint;
        }
        catch
        {
            // Signer details are a bonus; the trust verdict above stands.
        }
    }

    private static string? Clean(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        return s.Replace("\0", "").Trim();
    }

    private static SignatureInfo Clone(SignatureInfo s) => new()
    {
        Path = s.Path,
        Role = s.Role,
        ProcessId = s.ProcessId,
        Status = s.Status,
        Kind = s.Kind,
        Publisher = s.Publisher,
        Issuer = s.Issuer,
        Thumbprint = s.Thumbprint,
        Sha256 = s.Sha256,
        FileSize = s.FileSize,
        CompanyName = s.CompanyName,
        ProductName = s.ProductName,
        FileDescription = s.FileDescription,
        FileVersion = s.FileVersion,
        OriginalFileName = s.OriginalFileName,
        Detail = s.Detail
    };

    /// <summary>Thin, carefully laid-out wrappers over wintrust.dll.</summary>
    internal static class WinTrust
    {
        public const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        public const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        public const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
        public const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
        public const int TRUST_E_CERT_SIGNATURE = unchecked((int)0x80096004);
        public const int CRYPT_E_BAD_MSG = unchecked((int)0x8009200D);
        public const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
        public const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
        public const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
        public const int CERT_E_CHAINING = unchecked((int)0x800B010A);
        public const int CERT_E_REVOKED = unchecked((int)0x800B010C);
        public const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
        public const int CERT_E_UNTRUSTEDTESTROOT = unchecked((int)0x800B010D);
        public const int CERT_E_WRONG_USAGE = unchecked((int)0x800B0110);
        public const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);

        private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        private static readonly IntPtr NoWindow = new(-1);

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_CHOICE_CATALOG = 2;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
        private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

        [StructLayout(LayoutKind.Sequential)]
        internal struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pUnion;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WINTRUST_DATA data);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem,
            [MarshalAs(UnmanagedType.LPWStr)] string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext(out IntPtr catAdmin, IntPtr subsystem, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, SafeFileHandle file,
            ref uint hashSize, [Out] byte[]? hash, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(SafeFileHandle file, ref uint hashSize,
            [Out] byte[]? hash, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize,
            uint flags, IntPtr previousCatInfo);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CATALOG_INFO info, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

        public static int VerifyEmbedded(string path)
        {
            var pathPtr = Marshal.StringToHGlobalUni(path);
            var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            try
            {
                var file = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = pathPtr
                };
                Marshal.StructureToPtr(file, filePtr, false);
                var data = NewData(WTD_CHOICE_FILE, filePtr);
                return Run(ref data);
            }
            finally
            {
                Marshal.FreeHGlobal(filePtr);
                Marshal.FreeHGlobal(pathPtr);
            }
        }

        /// <summary>Looks the file up in the Windows catalogs (SHA-256 first, then SHA-1).</summary>
        public static (int Result, string? Catalog) VerifyCatalog(string path)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            foreach (var algorithm in new[] { "SHA256", null })
            {
                IntPtr admin;
                bool acquired = algorithm is null
                    ? CryptCATAdminAcquireContext(out admin, IntPtr.Zero, 0)
                    : CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0);
                if (!acquired || admin == IntPtr.Zero) continue;

                try
                {
                    uint size = 0;
                    byte[] hash;
                    bool hashed;
                    if (algorithm is null)
                    {
                        CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref size, null, 0);
                        if (size == 0) size = 20;
                        hash = new byte[size];
                        hashed = CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref size, hash, 0);
                    }
                    else
                    {
                        CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle, ref size, null, 0);
                        if (size == 0) size = 32;
                        hash = new byte[size];
                        hashed = CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle, ref size, hash, 0);
                    }
                    if (!hashed || size == 0) continue;

                    var catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                    if (catInfo == IntPtr.Zero) continue;
                    try
                    {
                        var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                        if (!CryptCATCatalogInfoFromContext(catInfo, ref info, 0) || string.IsNullOrEmpty(info.wszCatalogFile))
                            continue;
                        var memberTag = Convert.ToHexString(hash, 0, (int)size);
                        var rc = VerifyCatalogMember(info.wszCatalogFile, memberTag, path, fs.SafeFileHandle, hash, size, admin);
                        return (rc, info.wszCatalogFile);
                    }
                    finally
                    {
                        CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
                    }
                }
                finally
                {
                    CryptCATAdminReleaseContext(admin, 0);
                }
            }
            return (TRUST_E_NOSIGNATURE, null);
        }

        private static int VerifyCatalogMember(string catalog, string memberTag, string path, SafeFileHandle file,
            byte[] hash, uint hashSize, IntPtr admin)
        {
            var catalogPtr = Marshal.StringToHGlobalUni(catalog);
            var tagPtr = Marshal.StringToHGlobalUni(memberTag);
            var memberPtr = Marshal.StringToHGlobalUni(path);
            var hashPtr = Marshal.AllocHGlobal((int)hashSize);
            var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.Copy(hash, 0, hashPtr, (int)hashSize);
                var info = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    dwCatalogVersion = 0,
                    pcwszCatalogFilePath = catalogPtr,
                    pcwszMemberTag = tagPtr,
                    pcwszMemberFilePath = memberPtr,
                    hMemberFile = file.DangerousGetHandle(),
                    pbCalculatedFileHash = hashPtr,
                    cbCalculatedFileHash = hashSize,
                    pcCatalogContext = IntPtr.Zero,
                    hCatAdmin = admin
                };
                Marshal.StructureToPtr(info, infoPtr, false);
                var data = NewData(WTD_CHOICE_CATALOG, infoPtr);
                return Run(ref data);
            }
            finally
            {
                Marshal.FreeHGlobal(infoPtr);
                Marshal.FreeHGlobal(hashPtr);
                Marshal.FreeHGlobal(memberPtr);
                Marshal.FreeHGlobal(tagPtr);
                Marshal.FreeHGlobal(catalogPtr);
            }
        }

        private static WINTRUST_DATA NewData(uint choice, IntPtr union) => new()
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = choice,
            pUnion = union,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
        };

        private static int Run(ref WINTRUST_DATA data)
        {
            var action = GenericVerifyV2;
            int rc = WinVerifyTrust(NoWindow, ref action, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NoWindow, ref action, ref data);
            return rc;
        }
    }
}
