using System;
using CmdSpy.Core.Models;

namespace CmdSpy.Core;

/// <summary>
/// A live source of captured popups: either the capture engine itself, or a
/// follower that reads the log written by the CMD-spy boot service.
/// </summary>
public interface ICaptureFeed
{
    /// <summary>A new popup was captured.</summary>
    event EventHandler<CmdEvent>? EventCaptured;

    /// <summary>An existing capture gained detail (child, connection, exit, analysis).</summary>
    event EventHandler<CmdEvent>? EventUpdated;
}
