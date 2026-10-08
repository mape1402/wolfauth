using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Provides ASP.NET Core service registration helpers for WolfAuth.
/// </summary>
public static class WolfAuthServiceCollectionExtensions
{
    /// <summary>
    /// Adds WolfAuth services to an ASP.NET Core application.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">An optional configuration callback.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddWolfAuth(
        this IServiceCollection services,
        Action<WolfAuthAspNetCoreBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var builder = new WolfAuthAspNetCoreBuilder();
        configure?.Invoke(builder);

        var registry = builder.Registry.Build();

        services.AddLogging();
        services.AddAuthorization();
        services.AddHttpContextAccessor();
        services.TryAddSingleton(builder.Options);
        services.TryAddSingleton(builder.ClaimsMapping);
        services.TryAddSingleton<IWolfAuthPermissionRegistry>(registry);
        services.TryAddSingleton(builder.Store);
        services.TryAddSingleton<IWolfAuthAuthorizationStore>(serviceProvider =>
            serviceProvider.GetRequiredService<WolfAuthInMemoryPersistenceStore>());
        services.TryAddSingleton<IWolfAuthSubjectStore>(serviceProvider =>
            serviceProvider.GetRequiredService<WolfAuthInMemoryPersistenceStore>());
        services.TryAddSingleton<IWolfAuthAssignmentStore>(serviceProvider =>
            serviceProvider.GetRequiredService<WolfAuthInMemoryPersistenceStore>());
        services.TryAddSingleton<IWolfAuthAuditStore>(serviceProvider =>
            serviceProvider.GetRequiredService<WolfAuthInMemoryPersistenceStore>());
        services.TryAddSingleton<IWolfAuthUnitOfWork>(serviceProvider =>
            serviceProvider.GetRequiredService<WolfAuthInMemoryPersistenceStore>());
        services.TryAddSingleton<IWolfAuthAssignmentValidator, WolfAuthAssignmentValidator>();
        services.TryAddSingleton<IWolfAuthPolicyNameCodec, WolfAuthPolicyNameCodec>();
        services.TryAddSingleton<IWolfAuthSubjectResolver>(serviceProvider =>
            new WolfAuthClaimsPrincipalSubjectResolver(
                serviceProvider.GetRequiredService<WolfAuthClaimsPrincipalMappingOptions>()));
        services.TryAddScoped<IWolfAuthCurrentSubjectAccessor, WolfAuthCurrentSubjectAccessor>();
        services.TryAddScoped<IWolfAuthProvisioningService, WolfAuthProvisioningService>();
        services.TryAddScoped<IWolfAuthAdministrationService, WolfAuthAdministrationService>();

        if (builder.EnableEffectiveAccessCache)
        {
            services.TryAddSingleton(builder.CacheOptions);
            services.TryAddSingleton<IWolfAuthEffectiveAccessCache, WolfAuthMemoryEffectiveAccessCache>();
        }

        services.TryAddScoped<IWolfAuthEffectiveAccessResolver>(serviceProvider =>
            CreateEffectiveAccessResolver(serviceProvider, builder.EnableEffectiveAccessCache));
        services.TryAddScoped<IWolfAuthEvaluator>(CreateEvaluator);
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IAuthorizationHandler, WolfAuthPermissionAuthorizationHandler>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IAuthorizationHandler, WolfAuthPolicyAuthorizationHandler>());
        services.AddSingleton<IAuthorizationPolicyProvider, WolfAuthAuthorizationPolicyProvider>();

        return services;
    }

    /// <summary>
    /// Creates the effective access resolver used by ASP.NET Core registrations.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    /// <param name="enableCache">Whether to decorate the resolver with cache.</param>
    /// <returns>The configured effective access resolver.</returns>
    private static IWolfAuthEffectiveAccessResolver CreateEffectiveAccessResolver(
        IServiceProvider serviceProvider,
        bool enableCache)
    {
        var resolver = new WolfAuthEffectiveAccessResolver(
            serviceProvider.GetRequiredService<IWolfAuthAuthorizationStore>(),
            serviceProvider.GetRequiredService<IWolfAuthPermissionRegistry>(),
            serviceProvider.GetRequiredService<WolfAuthOptions>());

        if (!enableCache)
        {
            return resolver;
        }

        return new WolfAuthCachedEffectiveAccessResolver(
            resolver,
            serviceProvider.GetRequiredService<IWolfAuthEffectiveAccessCache>());
    }

    /// <summary>
    /// Creates the evaluator used by ASP.NET Core registrations.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    /// <returns>The configured evaluator.</returns>
    private static IWolfAuthEvaluator CreateEvaluator(IServiceProvider serviceProvider)
    {
        var evaluator = new WolfAuthEvaluator(
            serviceProvider.GetRequiredService<IWolfAuthPermissionRegistry>(),
            serviceProvider.GetRequiredService<IWolfAuthEffectiveAccessResolver>(),
            serviceProvider.GetRequiredService<WolfAuthOptions>(),
            serviceProvider.GetServices<IWolfAuthPolicyEvaluator>());

        return new WolfAuthAuditingEvaluator(
            evaluator,
            serviceProvider.GetRequiredService<IWolfAuthAuditStore>());
    }
}
