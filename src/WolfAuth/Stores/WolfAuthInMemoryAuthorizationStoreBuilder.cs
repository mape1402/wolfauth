namespace WolfAuth;

/// <summary>
/// Builds an in-memory authorization store for tests, demos, local development, and simple hosts.
/// </summary>
public sealed class WolfAuthInMemoryAuthorizationStoreBuilder
{
    private readonly List<WolfAuthSubjectId> _knownSubjectIds = [];
    private readonly List<WolfAuthAssignment> _assignments = [];

    /// <summary>
    /// Adds a known subject to the store.
    /// </summary>
    /// <param name="subjectId">The known subject identifier.</param>
    /// <returns>The current builder.</returns>
    public WolfAuthInMemoryAuthorizationStoreBuilder AddKnownSubject(WolfAuthSubjectId subjectId)
    {
        _knownSubjectIds.Add(subjectId);
        return this;
    }

    /// <summary>
    /// Adds a known subject to the store.
    /// </summary>
    /// <param name="subject">The known subject.</param>
    /// <returns>The current builder.</returns>
    public WolfAuthInMemoryAuthorizationStoreBuilder AddKnownSubject(WolfAuthSubject subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        return AddKnownSubject(subject.SubjectId);
    }

    /// <summary>
    /// Adds an assignment to the store.
    /// </summary>
    /// <param name="assignment">The assignment to add.</param>
    /// <returns>The current builder.</returns>
    public WolfAuthInMemoryAuthorizationStoreBuilder AddAssignment(WolfAuthAssignment assignment)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        _assignments.Add(assignment);
        return this;
    }

    /// <summary>
    /// Builds an in-memory authorization store.
    /// </summary>
    /// <returns>The built in-memory authorization store.</returns>
    public WolfAuthInMemoryAuthorizationStore Build()
    {
        return new WolfAuthInMemoryAuthorizationStore(_knownSubjectIds, _assignments);
    }
}
