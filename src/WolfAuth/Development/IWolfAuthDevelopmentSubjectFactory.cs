namespace WolfAuth;

/// <summary>
/// Creates normalized subjects for local development, tests, and demos.
/// </summary>
public interface IWolfAuthDevelopmentSubjectFactory
{
    /// <summary>
    /// Creates a normalized subject from a development subject request.
    /// </summary>
    /// <param name="request">The development subject request.</param>
    /// <returns>The created normalized subject.</returns>
    WolfAuthSubject Create(WolfAuthDevelopmentSubjectRequest request);
}
