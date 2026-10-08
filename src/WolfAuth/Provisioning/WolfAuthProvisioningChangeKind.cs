namespace WolfAuth;

/// <summary>
/// Identifies the kind of change produced by provisioning.
/// </summary>
public enum WolfAuthProvisioningChangeKind
{
    /// <summary>
    /// A new subject was created.
    /// </summary>
    SubjectCreated = 0,

    /// <summary>
    /// An existing subject was updated.
    /// </summary>
    SubjectUpdated = 1,

    /// <summary>
    /// A subject was deactivated.
    /// </summary>
    SubjectDeactivated = 2
}
