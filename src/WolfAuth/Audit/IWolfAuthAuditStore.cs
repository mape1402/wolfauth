namespace WolfAuth;

/// <summary>
/// Stores and retrieves WolfAuth audit records.
/// </summary>
public interface IWolfAuthAuditStore
{
    /// <summary>
    /// Appends an audit record.
    /// </summary>
    /// <param name="record">The audit record to append.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when the record has been appended.</returns>
    ValueTask AppendAsync(WolfAuthAuditRecord record, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets recent audit records.
    /// </summary>
    /// <param name="take">The maximum number of records to return.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The recent audit records ordered from newest to oldest.</returns>
    ValueTask<IReadOnlyList<WolfAuthAuditRecord>> GetRecentAsync(
        int take = 100,
        CancellationToken cancellationToken = default);
}
