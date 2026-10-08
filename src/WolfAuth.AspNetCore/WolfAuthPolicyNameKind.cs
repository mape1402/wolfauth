namespace WolfAuth.AspNetCore;

/// <summary>
/// Identifies the kind of WolfAuth authorization policy name.
/// </summary>
public enum WolfAuthPolicyNameKind
{
    /// <summary>
    /// The policy name does not belong to WolfAuth.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The policy name represents a permission check.
    /// </summary>
    Permission = 1,

    /// <summary>
    /// The policy name represents a policy check.
    /// </summary>
    Policy = 2
}
