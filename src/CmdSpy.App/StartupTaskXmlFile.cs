using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CmdSpy.App;

/// <summary>
/// A short-lived XML file for the schtasks compatibility path. It is created
/// atomically beneath the protected Windows system directory, with an explicit
/// Administrators owner and a protected Administrators/SYSTEM-only DACL. A
/// non-elevated process (even the same user) cannot replace the privileged input
/// or use file ownership to grant itself write access.
/// </summary>
internal sealed class StartupTaskXmlFile : IDisposable
{
    private const string SecurityDescriptor = "O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)";
    private FileStream? _readLock;

    public string FilePath { get; }

    private StartupTaskXmlFile(string path, FileStream readLock)
    {
        FilePath = path;
        _readLock = readLock;
    }

    public static StartupTaskXmlFile Create(string taskXml)
    {
        var path = Path.Combine(Environment.SystemDirectory, $"CmdSpy-task-{Guid.NewGuid():N}.xml");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(SecurityDescriptor, 1, out var descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not protect the temporary task definition.");

        try
        {
            var security = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor,
                InheritHandle = false
            };
            // CREATE_NEW refuses existing files, including pre-created links.
            // Apply the owner and DACL at creation, never after writing the XML.
            using var handle = CreateFileW(path, 0x40000000, 1, ref security, 1, 0x100, IntPtr.Zero);
            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the protected temporary task definition.");

            try
            {
                using (var stream = new FileStream(handle, FileAccess.Write))
                using (var writer = new StreamWriter(stream, Encoding.Unicode))
                    writer.Write(taskXml);
                handle.Dispose();

                // schtasks can open a normal read handle. Keep writes and
                // deletion blocked until it finishes consuming the file.
                return new StartupTaskXmlFile(path, new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
            }
            catch
            {
                handle.Dispose();
                DeleteIfPresent(path);
                throw;
            }
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    public void Dispose()
    {
        if (_readLock is null) return;
        _readLock.Dispose();
        _readLock = null;
        DeleteIfPresent(FilePath);
    }

    private static void DeleteIfPresent(string path)
    {
        // A cleanup failure must not turn successful registration into a retry.
        // Any remaining file still has the restricted owner and DACL above.
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string text, uint revision, out IntPtr descriptor, out uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string path, uint desiredAccess, uint shareMode, ref SecurityAttributes security,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
