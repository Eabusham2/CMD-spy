using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace CmdSpy.Core;

/// <summary>
/// Makes sure only one CMD-spy window runs on the machine. The first copy owns
/// a named mutex in a private Windows object namespace; any later start in the
/// same security boundary asks it to show its window and exits, so there is
/// never a second capture session writing the same logs.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    public const string DefaultName = "CmdSpy.SingleInstance";

    private readonly Mutex? _mutex;
    private readonly EventWaitHandle? _activate;
    private readonly PrivateObjectNamespace? _namespace;
    private readonly string? _eventName;
    private RegisteredWaitHandle? _registration;

    public SingleInstance(string name = DefaultName)
    {
        // A fixed Global\ name can be created by a less-privileged process before
        // CMD-spy starts. The private namespace authenticates named-object peers
        // with both their principal and integrity level, so a medium-integrity
        // process cannot occupy the elevated monitor's mutex or activation event.
        _namespace = PrivateObjectNamespace.TryCreate();
        if (_namespace is null)
        {
            IsFirst = true;    // namespace failure must never suppress monitoring
            return;
        }

        _eventName = _namespace.Qualify(name + ".Activate");
        try
        {
            _mutex = new Mutex(initiallyOwned: true, _namespace.Qualify(name), out bool createdNew);
            IsFirst = createdNew;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or
                                   WaitHandleCannotBeOpenedException or PlatformNotSupportedException)
        {
            IsFirst = true;    // an unusable object is not proof of a genuine copy
        }

        if (IsFirst)
        {
            try { _activate = new EventWaitHandle(false, EventResetMode.AutoReset, _eventName); }
            catch { /* activation requests just won't be received */ }
        }
    }

    /// <summary>True for the copy that gets to run.</summary>
    public bool IsFirst { get; }

    /// <summary>Asks the running copy to bring its window forward. Returns false if it couldn't be reached.</summary>
    public bool ActivateFirst()
    {
        if (_eventName is null) return false;

        try
        {
            if (!EventWaitHandle.TryOpenExisting(_eventName, out var handle)) return false;
            using (handle) handle.Set();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Calls <paramref name="onActivate"/> (on a thread-pool thread) whenever another start asks this copy to show itself.</summary>
    public void OnActivationRequested(Action onActivate)
    {
        if (_activate is null || _registration is not null) return;
        _registration = ThreadPool.RegisterWaitForSingleObject(_activate, (_, _) =>
        {
            try { onActivate(); } catch { }
        }, null, Timeout.Infinite, executeOnlyOnce: false);
    }

    public void Dispose()
    {
        _registration?.Unregister(null);
        _registration = null;
        _activate?.Dispose();
        if (_mutex is not null)
        {
            if (IsFirst)
            {
                try { _mutex.ReleaseMutex(); } catch { /* released by another thread or already gone */ }
            }
            _mutex.Dispose();
        }
        _namespace?.Dispose();
    }

    /// <summary>
    /// Owns a Windows private object namespace whose boundary matches the
    /// current principal and mandatory integrity level.
    /// </summary>
    private sealed class PrivateObjectNamespace : IDisposable
    {
        private const string Alias = "CmdSpy.Private.v1";
        private const string BoundaryName = "CmdSpy.SingleInstance.v1";
        private const int ErrorAlreadyExists = 183;
        private const uint PrivateNamespaceFlagDestroy = 0x1;
        private const int TokenIntegrityLevel = 25;
        private const uint SecurityDescriptorRevision = 1;

        private IntPtr _handle;
        private readonly bool _created;

        private PrivateObjectNamespace(IntPtr handle, bool created)
        {
            _handle = handle;
            _created = created;
        }

        public string Qualify(string objectName) => Alias + "\\" + objectName;

        public static PrivateObjectNamespace? TryCreate()
        {
            if (!OperatingSystem.IsWindows()) return null;

            IntPtr boundary = IntPtr.Zero;
            IntPtr boundarySid = IntPtr.Zero;
            IntPtr tokenInformation = IntPtr.Zero;
            IntPtr securityDescriptor = IntPtr.Zero;

            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                var boundaryPrincipal = principal.IsInRole(WindowsBuiltInRole.Administrator)
                    ? new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
                    : identity.User;
                if (boundaryPrincipal is null) return null;

                boundary = CreateBoundaryDescriptor(BoundaryName, 0);
                if (boundary == IntPtr.Zero) return null;

                boundarySid = CopySid(boundaryPrincipal);
                if (!AddSidToBoundaryDescriptor(ref boundary, boundarySid)) return null;

                GetTokenInformation(identity.AccessToken.DangerousGetHandle(), TokenIntegrityLevel,
                    IntPtr.Zero, 0, out int tokenInformationLength);
                if (tokenInformationLength <= 0) return null;

                tokenInformation = Marshal.AllocHGlobal(tokenInformationLength);
                if (!GetTokenInformation(identity.AccessToken.DangerousGetHandle(), TokenIntegrityLevel,
                        tokenInformation, tokenInformationLength, out _))
                    return null;

                var mandatoryLabel = Marshal.PtrToStructure<TokenMandatoryLabel>(tokenInformation);
                if (mandatoryLabel.Label.Sid == IntPtr.Zero ||
                    !AddIntegrityLabelToBoundaryDescriptor(ref boundary, mandatoryLabel.Label.Sid))
                    return null;

                // Protect the namespace itself as well as its principal/integrity
                // boundary. A filtered administrator token cannot use an allow ACE
                // for the disabled Administrators SID.
                string sddl = $"D:P(A;;GA;;;SY)(A;;GA;;;{boundaryPrincipal.Value})";
                if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                        sddl, SecurityDescriptorRevision, out securityDescriptor, out _))
                    return null;

                var attributes = new SecurityAttributes
                {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = securityDescriptor,
                    InheritHandle = 0
                };

                IntPtr namespaceHandle = CreatePrivateNamespace(ref attributes, boundary, Alias);
                bool created = namespaceHandle != IntPtr.Zero;
                if (!created)
                {
                    if (Marshal.GetLastWin32Error() != ErrorAlreadyExists) return null;
                    namespaceHandle = OpenPrivateNamespace(boundary, Alias);
                    if (namespaceHandle == IntPtr.Zero) return null;
                }

                return new PrivateObjectNamespace(namespaceHandle, created);
            }
            catch
            {
                return null;
            }
            finally
            {
                if (securityDescriptor != IntPtr.Zero) LocalFree(securityDescriptor);
                if (tokenInformation != IntPtr.Zero) Marshal.FreeHGlobal(tokenInformation);
                if (boundarySid != IntPtr.Zero) Marshal.FreeHGlobal(boundarySid);
                if (boundary != IntPtr.Zero) DeleteBoundaryDescriptor(boundary);
            }
        }

        private static IntPtr CopySid(SecurityIdentifier sid)
        {
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            IntPtr copy = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, copy, bytes.Length);
            return copy;
        }

        public void Dispose()
        {
            IntPtr handle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
            if (handle != IntPtr.Zero)
                ClosePrivateNamespace(handle, _created ? PrivateNamespaceFlagDestroy : 0);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            public int InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SidAndAttributes
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenMandatoryLabel
        {
            public SidAndAttributes Label;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateBoundaryDescriptorW", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr CreateBoundaryDescriptor(string name, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "AddSIDToBoundaryDescriptor", SetLastError = true)]
        private static extern bool AddSidToBoundaryDescriptor(ref IntPtr boundaryDescriptor, IntPtr requiredSid);

        [DllImport("kernel32.dll", EntryPoint = "AddIntegrityLabelToBoundaryDescriptor", SetLastError = true)]
        private static extern bool AddIntegrityLabelToBoundaryDescriptor(
            ref IntPtr boundaryDescriptor, IntPtr integrityLabel);

        [DllImport("kernel32.dll", EntryPoint = "DeleteBoundaryDescriptor")]
        private static extern void DeleteBoundaryDescriptor(IntPtr boundaryDescriptor);

        [DllImport("kernel32.dll", EntryPoint = "CreatePrivateNamespaceW", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr CreatePrivateNamespace(
            ref SecurityAttributes privateNamespaceAttributes, IntPtr boundaryDescriptor, string aliasPrefix);

        [DllImport("kernel32.dll", EntryPoint = "OpenPrivateNamespaceW", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr OpenPrivateNamespace(IntPtr boundaryDescriptor, string aliasPrefix);

        [DllImport("kernel32.dll", EntryPoint = "ClosePrivateNamespace")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool ClosePrivateNamespace(IntPtr handle, uint flags);

        [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation,
            int tokenInformationLength, out int returnLength);

        [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor, uint stringSdRevision,
            out IntPtr securityDescriptor, out uint securityDescriptorSize);

        [DllImport("kernel32.dll", EntryPoint = "LocalFree")]
        private static extern IntPtr LocalFree(IntPtr memory);
    }
}
