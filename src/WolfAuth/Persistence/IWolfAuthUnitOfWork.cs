namespace WolfAuth;

/// <summary>
/// Represents a persistence boundary that can commit pending WolfAuth changes.
/// </summary>
public interface IWolfAuthUnitOfWork
{
    /// <summary>
    /// Commits pending store changes.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The number of persisted state entries when the backing store can report it.</returns>
    ValueTask<int> CommitAsync(CancellationToken cancellationToken = default);
}
