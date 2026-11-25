using System;

namespace CmdSpy.Core;

/// <summary>Uses the direct Task Scheduler API first, retaining schtasks as a compatibility path.</summary>
public static class StartupTaskRegistration
{
    /// <returns>True when the compatibility registration was needed.</returns>
    public static bool Register(
        string taskXml,
        string user,
        Action<string, string> registerWithCom,
        Action<string, string> registerWithSchtasks)
    {
        ArgumentNullException.ThrowIfNull(registerWithCom);
        ArgumentNullException.ThrowIfNull(registerWithSchtasks);

        try
        {
            registerWithCom(taskXml, user);
            return false;
        }
        catch (Exception comFailure)
        {
            try
            {
                // Reuse the exact definition and identity. A successful COM
                // registration never reaches this path or gets overwritten.
                registerWithSchtasks(taskXml, user);
                return true;
            }
            catch (Exception schtasksFailure)
            {
                throw new InvalidOperationException(
                    $"Task Scheduler COM registration failed: {comFailure.Message} " +
                    $"The schtasks compatibility registration also failed: {schtasksFailure.Message}",
                    new AggregateException(comFailure, schtasksFailure));
            }
        }
    }
}
