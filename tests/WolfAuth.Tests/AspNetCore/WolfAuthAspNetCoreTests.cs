using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WolfAuth.AspNetCore;
using HttpJsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;

namespace WolfAuth.Tests.AspNetCore;

/// <summary>
/// Tests ASP.NET Core integration.
/// </summary>
public sealed class WolfAuthAspNetCoreTests
{
    /// <summary>
    /// Verifies that WolfAuth policy names round-trip through the codec.
    /// </summary>
    [Fact]
    public void PolicyNameCodec_RoundTripsPermissionPolicyNames()
    {
        var codec = new WolfAuthPolicyNameCodec();

        var policyName = codec.CreatePermissionPolicyName(
            "contracts.events.view",
            "environment:qa");
        var parsed = codec.TryParse(policyName, out var parsedPolicyName);

        Assert.True(parsed);
        Assert.Equal(WolfAuthPolicyNameKind.Permission, parsedPolicyName.Kind);
        Assert.Equal("contracts.events.view", parsedPolicyName.PermissionKey?.ToString());
        Assert.Equal("environment:qa", parsedPolicyName.ScopeKey.ToString());
    }

    /// <summary>
    /// Verifies that WolfAuth policy names round-trip for host policies and reject unknown formats.
    /// </summary>
    [Fact]
    public void PolicyNameCodec_ParsesPoliciesAndRejectsUnknownNames()
    {
        var codec = new WolfAuthPolicyNameCodec();

        var policyName = codec.CreatePolicyPolicyName("events.promote");
        var parsed = codec.TryParse(policyName, out var parsedPolicyName);
        var parsedWithoutScope = codec.TryParse(
            "WolfAuth:Permission:contracts.events.view:",
            out var parsedPolicyNameWithoutScope);
        var shortName = codec.TryParse("WolfAuth", out var shortPolicyName);
        var unsupportedSegment = codec.TryParse("WolfAuth:Unsupported:events.promote", out var unsupportedPolicyName);
        var unknown = codec.TryParse("Other:Policy:events.promote", out var unknownPolicyName);

        Assert.True(parsed);
        Assert.Equal(WolfAuthPolicyNameKind.Policy, parsedPolicyName.Kind);
        Assert.Equal("events.promote", parsedPolicyName.PolicyKey?.ToString());
        Assert.Equal(WolfAuthScopeKey.Global, parsedPolicyName.ScopeKey);
        Assert.True(parsedWithoutScope);
        Assert.Equal(WolfAuthScopeKey.Global, parsedPolicyNameWithoutScope.ScopeKey);
        Assert.False(shortName);
        Assert.Equal(WolfAuthPolicyNameKind.Unknown, shortPolicyName.Kind);
        Assert.False(unsupportedSegment);
        Assert.Equal(WolfAuthPolicyNameKind.Unknown, unsupportedPolicyName.Kind);
        Assert.False(unknown);
        Assert.Equal(WolfAuthPolicyNameKind.Unknown, unknownPolicyName.Kind);
    }

    /// <summary>
    /// Verifies that the attribute emits a WolfAuth policy name.
    /// </summary>
    [Fact]
    public void PermissionAttribute_EmitsWolfAuthPolicyName()
    {
        var attribute = new WolfAuthPermissionAttribute("contracts.events.view", "tenant:one");

        Assert.StartsWith("WolfAuth:Permission:", attribute.Policy, StringComparison.Ordinal);
        Assert.Equal("contracts.events.view", attribute.PermissionKey);
        Assert.Equal("tenant:one", attribute.ScopeKey);
    }

    /// <summary>
    /// Verifies that attributes use global scope when no scope is provided.
    /// </summary>
    [Fact]
    public void Attributes_DefaultToGlobalScope()
    {
        var permissionAttribute = new WolfAuthPermissionAttribute("contracts.events.view");
        var policyAttribute = new WolfAuthPolicyAttribute("events.promote");
        var scopedPolicyAttribute = new WolfAuthPolicyAttribute("events.promote", "tenant:one");

        Assert.Equal(WolfAuthScopeKey.Global.ToString(), permissionAttribute.ScopeKey);
        Assert.StartsWith("WolfAuth:Permission:", permissionAttribute.Policy, StringComparison.Ordinal);
        Assert.Equal("contracts.events.view", permissionAttribute.PermissionKey);
        Assert.Equal(WolfAuthScopeKey.Global.ToString(), policyAttribute.ScopeKey);
        Assert.StartsWith("WolfAuth:Policy:", policyAttribute.Policy, StringComparison.Ordinal);
        Assert.Equal("events.promote", policyAttribute.PolicyKey);
        Assert.Equal("tenant:one", scopedPolicyAttribute.ScopeKey);
    }

    /// <summary>
    /// Verifies dynamic authorization policy provider behavior.
    /// </summary>
    [Fact]
    public async Task AuthorizationPolicyProvider_BuildsWolfAuthPoliciesAndFallsBack()
    {
        var options = Options.Create(new AuthorizationOptions());
        options.Value.AddPolicy("fallback-policy", policy => policy.RequireAuthenticatedUser());
        var provider = new WolfAuthAuthorizationPolicyProvider(options, new WolfAuthPolicyNameCodec());
        var codec = new WolfAuthPolicyNameCodec();

        var defaultPolicy = await provider.GetDefaultPolicyAsync();
        var fallbackPolicy = await provider.GetPolicyAsync("fallback-policy");
        var permissionPolicy = await provider.GetPolicyAsync(codec.CreatePermissionPolicyName("contracts.events.view"));
        var policyPolicy = await provider.GetPolicyAsync(codec.CreatePolicyPolicyName("events.promote"));
        var unknownPolicy = await provider.GetPolicyAsync("missing-policy");
        var fallback = await provider.GetFallbackPolicyAsync();

        Assert.NotNull(defaultPolicy);
        Assert.NotNull(fallbackPolicy);
        Assert.NotNull(permissionPolicy);
        Assert.NotNull(policyPolicy);
        Assert.Null(unknownPolicy);
        Assert.Null(fallback);
        Assert.Contains(permissionPolicy.Requirements, requirement => requirement is WolfAuthPermissionRequirement);
        Assert.Contains(policyPolicy.Requirements, requirement => requirement is WolfAuthPolicyRequirement);
    }

    /// <summary>
    /// Verifies that parsed but unsupported WolfAuth policy names return no ASP.NET Core policy.
    /// </summary>
    [Fact]
    public async Task AuthorizationPolicyProvider_ReturnsNull_ForUnsupportedParsedPolicyKinds()
    {
        var provider = new WolfAuthAuthorizationPolicyProvider(
            Options.Create(new AuthorizationOptions()),
            new UnsupportedPolicyNameCodec());

        var policy = await provider.GetPolicyAsync("unsupported");

        Assert.Null(policy);
    }

    /// <summary>
    /// Verifies default and cache-disabled service registration paths.
    /// </summary>
    [Fact]
    public void AddWolfAuth_RegistersDefaultsAndSupportsDisablingCache()
    {
        var defaultServices = new ServiceCollection();
        var cacheDisabledServices = new ServiceCollection();

        var defaultReturnedServices = defaultServices.AddWolfAuth();
        var cacheDisabledReturnedServices = cacheDisabledServices.AddWolfAuth(builder =>
        {
            builder.EnableEffectiveAccessCache = false;
        });

        using var defaultProvider = defaultServices.BuildServiceProvider();
        using var cacheDisabledProvider = cacheDisabledServices.BuildServiceProvider();

        var defaultResolver = defaultProvider.GetRequiredService<IWolfAuthEffectiveAccessResolver>();
        var cacheDisabledResolver = cacheDisabledProvider.GetRequiredService<IWolfAuthEffectiveAccessResolver>();

        Assert.Same(defaultServices, defaultReturnedServices);
        Assert.Same(cacheDisabledServices, cacheDisabledReturnedServices);
        Assert.IsType<WolfAuthCachedEffectiveAccessResolver>(defaultResolver);
        Assert.IsType<WolfAuthEffectiveAccessResolver>(cacheDisabledResolver);
        Assert.NotNull(defaultProvider.GetRequiredService<IWolfAuthAdminEndpointHandler>());
        Assert.Throws<ArgumentNullException>(() => WolfAuthServiceCollectionExtensions.AddWolfAuth(null!));
    }

    /// <summary>
    /// Verifies WolfAuth key JSON converters round-trip key values as strings.
    /// </summary>
    [Fact]
    public void AddWolfAuth_ConfiguresJsonStringConvertersForWolfAuthKeys()
    {
        var services = new ServiceCollection();
        services.AddWolfAuth();
        using var provider = services.BuildServiceProvider();
        var jsonOptions = provider.GetRequiredService<IOptions<HttpJsonOptions>>().Value.SerializerOptions;
        var wrapper = new WolfAuthKeyJsonWrapper
        {
            SubjectId = "subject-1",
            Provider = "oidc",
            ExternalUserId = "external-1",
            ExternalGroupKey = "reviewers",
            PermissionKey = "contracts.events.view",
            RoleKey = "reader",
            ScopeKey = "tenant:one",
            PolicyKey = "events.promote"
        };
        var assignment = SubjectPermission("assignment-1", TestSubject("subject-1"), "contracts.events.view");

        var wrapperJson = JsonSerializer.Serialize(wrapper, jsonOptions);
        var assignmentJson = JsonSerializer.Serialize(assignment, jsonOptions);
        var wrapperRoundTrip = JsonSerializer.Deserialize<WolfAuthKeyJsonWrapper>(wrapperJson, jsonOptions);
        var assignmentRoundTrip = JsonSerializer.Deserialize<WolfAuthAssignment>(assignmentJson, jsonOptions);

        Assert.Contains("\"subjectId\":\"subject-1\"", wrapperJson, StringComparison.Ordinal);
        Assert.Contains("\"permissionKey\":\"contracts.events.view\"", assignmentJson, StringComparison.Ordinal);
        Assert.NotNull(wrapperRoundTrip);
        Assert.Equal("oidc", wrapperRoundTrip.Provider.ToString());
        Assert.Equal("external-1", wrapperRoundTrip.ExternalUserId.ToString());
        Assert.Equal("reviewers", wrapperRoundTrip.ExternalGroupKey.ToString());
        Assert.Equal("contracts.events.view", wrapperRoundTrip.PermissionKey.ToString());
        Assert.Equal("reader", wrapperRoundTrip.RoleKey.ToString());
        Assert.Equal("tenant:one", wrapperRoundTrip.ScopeKey.ToString());
        Assert.Equal("events.promote", wrapperRoundTrip.PolicyKey.ToString());
        Assert.NotNull(assignmentRoundTrip);
        Assert.Equal("subject-1", assignmentRoundTrip.SubjectId?.ToString());
        Assert.Equal("contracts.events.view", assignmentRoundTrip.PermissionKey?.ToString());
    }

    /// <summary>
    /// Verifies WolfAuth key JSON converters reject invalid JSON shapes.
    /// </summary>
    [Fact]
    public void AddWolfAuth_ConfiguredJsonConvertersRejectInvalidKeyShapes()
    {
        var services = new ServiceCollection();
        services.AddWolfAuth();
        using var provider = services.BuildServiceProvider();
        var jsonOptions = provider.GetRequiredService<IOptions<HttpJsonOptions>>().Value.SerializerOptions;
        var converterFactory = Assert.Single(jsonOptions.Converters, converter => converter.CanConvert(typeof(WolfAuthSubjectId)));

        Assert.False(converterFactory.CanConvert(typeof(string)));
        Assert.Throws<JsonException>(DeserializeNumber);
        Assert.Throws<JsonException>(DeserializeBlankString);
        Assert.Throws<NotSupportedException>(CreateUnsupportedConverter);

        void DeserializeNumber()
        {
            JsonSerializer.Deserialize<WolfAuthSubjectJsonWrapper>("{\"subjectId\":5}", jsonOptions);
        }

        void DeserializeBlankString()
        {
            JsonSerializer.Deserialize<WolfAuthSubjectJsonWrapper>("{\"subjectId\":\" \"}", jsonOptions);
        }

        void CreateUnsupportedConverter()
        {
            ((System.Text.Json.Serialization.JsonConverterFactory)converterFactory).CreateConverter(
                typeof(DateTimeOffset),
                jsonOptions);
        }
    }

    /// <summary>
    /// Verifies that ASP.NET Core authorization succeeds through WolfAuth handlers.
    /// </summary>
    [Fact]
    public async Task AuthorizationService_AllowsRegisteredPermission()
    {
        var subject = TestSubject("subject-1");
        var services = new ServiceCollection();
        services.AddWolfAuth(builder =>
        {
            builder.Registry.AddPermission("contracts.events.view");
            builder.Store = new WolfAuthInMemoryPersistenceStore(
                [new WolfAuthStoredSubject { Subject = subject }],
                [SubjectPermission("assignment-1", subject, "contracts.events.view")]);
        });
        using var serviceProvider = services.BuildServiceProvider();
        var principal = TestPrincipal("subject-1");
        serviceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider,
            User = principal
        };
        var authorizationService = serviceProvider.GetRequiredService<IAuthorizationService>();
        var policyName = serviceProvider
            .GetRequiredService<IWolfAuthPolicyNameCodec>()
            .CreatePermissionPolicyName("contracts.events.view");

        var result = await authorizationService.AuthorizeAsync(principal, null, policyName);

        Assert.True(result.Succeeded);
    }

    /// <summary>
    /// Verifies current subject accessor null, failure, success, and cache paths.
    /// </summary>
    [Fact]
    public async Task CurrentSubjectAccessor_ResolvesAndCachesSubjects()
    {
        var subject = TestSubject("subject-1");
        var httpContextAccessor = new HttpContextAccessor();
        var resolver = new TestSubjectResolver(WolfAuthSubjectResolutionResult.Success(subject));
        var accessor = new WolfAuthCurrentSubjectAccessor(httpContextAccessor, resolver);

        var withoutContext = await accessor.GetCurrentSubjectAsync();
        httpContextAccessor.HttpContext = new DefaultHttpContext
        {
            User = TestPrincipal("subject-1")
        };
        var first = await accessor.GetCurrentSubjectAsync();
        var second = await accessor.GetCurrentSubjectAsync();

        var failingAccessor = new WolfAuthCurrentSubjectAccessor(
            new HttpContextAccessor
            {
                HttpContext = new DefaultHttpContext
                {
                    User = TestPrincipal("subject-2")
                }
            },
            new TestSubjectResolver(WolfAuthSubjectResolutionResult.Failure(
                WolfAuthSubjectResolutionFailureReason.Unauthenticated)));

        var failure = await failingAccessor.GetCurrentSubjectAsync();

        Assert.Null(withoutContext);
        Assert.Same(subject, first);
        Assert.Same(subject, second);
        Assert.Equal(1, resolver.CallCount);
        Assert.Null(failure);
    }

    /// <summary>
    /// Verifies permission and policy handlers allow and deny as expected.
    /// </summary>
    [Fact]
    public async Task AuthorizationHandlers_HandleAllowAndDenyPaths()
    {
        var subject = TestSubject("subject-1");
        var allowingEvaluator = new TestEvaluator(WolfAuthEvaluationResult.Allow(WolfAuthEvaluationReason.Allowed));
        var denyingEvaluator = new TestEvaluator(WolfAuthEvaluationResult.Deny(WolfAuthEvaluationReason.DeniedMissingPermission));
        var subjectAccessor = new TestCurrentSubjectAccessor(subject);
        var nullSubjectAccessor = new TestCurrentSubjectAccessor(null);
        var permissionRequirement = new WolfAuthPermissionRequirement("contracts.events.view", WolfAuthScopeKey.Global);
        var policyRequirement = new WolfAuthPolicyRequirement("events.promote", WolfAuthScopeKey.Global);

        var permissionAllowContext = new AuthorizationHandlerContext([permissionRequirement], new ClaimsPrincipal(), null);
        await new WolfAuthPermissionAuthorizationHandler(subjectAccessor, allowingEvaluator)
            .HandleAsync(permissionAllowContext);

        var permissionDenyContext = new AuthorizationHandlerContext([permissionRequirement], new ClaimsPrincipal(), null);
        await new WolfAuthPermissionAuthorizationHandler(subjectAccessor, denyingEvaluator)
            .HandleAsync(permissionDenyContext);

        var permissionNullContext = new AuthorizationHandlerContext([permissionRequirement], new ClaimsPrincipal(), null);
        await new WolfAuthPermissionAuthorizationHandler(nullSubjectAccessor, allowingEvaluator)
            .HandleAsync(permissionNullContext);

        var policyAllowContext = new AuthorizationHandlerContext([policyRequirement], new ClaimsPrincipal(), null);
        await new WolfAuthPolicyAuthorizationHandler(subjectAccessor, allowingEvaluator)
            .HandleAsync(policyAllowContext);

        var policyDenyContext = new AuthorizationHandlerContext([policyRequirement], new ClaimsPrincipal(), null);
        await new WolfAuthPolicyAuthorizationHandler(subjectAccessor, denyingEvaluator)
            .HandleAsync(policyDenyContext);

        var policyNullContext = new AuthorizationHandlerContext([policyRequirement], new ClaimsPrincipal(), null);
        await new WolfAuthPolicyAuthorizationHandler(nullSubjectAccessor, allowingEvaluator)
            .HandleAsync(policyNullContext);

        Assert.True(permissionAllowContext.HasSucceeded);
        Assert.False(permissionDenyContext.HasSucceeded);
        Assert.False(permissionNullContext.HasSucceeded);
        Assert.True(policyAllowContext.HasSucceeded);
        Assert.False(policyDenyContext.HasSucceeded);
        Assert.False(policyNullContext.HasSucceeded);
    }

    /// <summary>
    /// Verifies middleware and application builder extension paths.
    /// </summary>
    [Fact]
    public async Task MiddlewareAndBuilderExtension_ResolveSubjectAndContinuePipeline()
    {
        var calledNext = false;
        var accessor = new TestCurrentSubjectAccessor(TestSubject("subject-1"));
        var middleware = new WolfAuthMiddleware(_ =>
        {
            calledNext = true;
            return Task.CompletedTask;
        });
        var services = new ServiceCollection().BuildServiceProvider();
        var applicationBuilder = new ApplicationBuilder(services);

        var returnedBuilder = applicationBuilder.UseWolfAuth();
        await middleware.InvokeAsync(new DefaultHttpContext(), accessor);

        Assert.Same(applicationBuilder, returnedBuilder);
        Assert.True(calledNext);
        Assert.Equal(1, accessor.CallCount);
        Assert.Throws<ArgumentNullException>(() => WolfAuthApplicationBuilderExtensions.UseWolfAuth(null!));
    }

    /// <summary>
    /// Verifies admin endpoint handlers return expected result status codes.
    /// </summary>
    [Fact]
    public async Task AdminEndpointHandler_ReturnsExpectedResults()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }]);
        var registry = new WolfAuthPermissionRegistryBuilder()
            .AddPermission("contracts.events.view")
            .Build();
        var evaluator = new WolfAuthEvaluator(
            registry,
            new WolfAuthEffectiveAccessResolver(store, registry));
        var handler = new WolfAuthAdminEndpointHandler(
            store,
            new WolfAuthAssignmentValidator(registry),
            new WolfAuthAdministrationService(
                store,
                new WolfAuthAssignmentValidator(registry),
                evaluator,
                store,
                store));
        var validAssignment = SubjectPermission("assignment-1", subject, "contracts.events.view");
        var invalidAssignment = SubjectPermission("assignment-2", subject, "unknown.permission");

        var accessStatus = await ExecuteAsync(await handler.GetEffectiveAccessAsync("subject-1"));
        var missingAccessStatus = await ExecuteAsync(await handler.GetEffectiveAccessAsync("missing"));
        var validValidationStatus = await ExecuteAsync(await handler.ValidateAssignmentAsync(validAssignment));
        var invalidValidationStatus = await ExecuteAsync(await handler.ValidateAssignmentAsync(invalidAssignment));
        var upsertStatus = await ExecuteAsync(await handler.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            Assignment = validAssignment
        }));
        var invalidUpsertStatus = await ExecuteAsync(await handler.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            Assignment = invalidAssignment
        }));
        var removeStatus = await ExecuteAsync(await handler.RemoveAssignmentAsync("assignment-1"));
        var removeMissingStatus = await ExecuteAsync(await handler.RemoveAssignmentAsync("assignment-1"));

        Assert.Equal(StatusCodes.Status200OK, accessStatus);
        Assert.Equal(StatusCodes.Status404NotFound, missingAccessStatus);
        Assert.Equal(StatusCodes.Status200OK, validValidationStatus);
        Assert.Equal(StatusCodes.Status400BadRequest, invalidValidationStatus);
        Assert.Equal(StatusCodes.Status200OK, upsertStatus);
        Assert.Equal(StatusCodes.Status400BadRequest, invalidUpsertStatus);
        Assert.Equal(StatusCodes.Status204NoContent, removeStatus);
        Assert.Equal(StatusCodes.Status404NotFound, removeMissingStatus);
    }

    /// <summary>
    /// Verifies endpoint route mapping can be configured.
    /// </summary>
    [Fact]
    public void EndpointRouteBuilder_MapsAdminApi()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddWolfAuth(wolf => wolf.Registry.AddPermission("contracts.events.view"));
        using var app = builder.Build();

        var group = app.MapWolfAuthAdminApi("/security");

        Assert.NotNull(group);
        Assert.Throws<ArgumentNullException>(() => WolfAuthEndpointRouteBuilderExtensions.MapWolfAuthAdminApi(null!));
    }

    /// <summary>
    /// Creates an authenticated test principal.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <returns>The authenticated principal.</returns>
    private static ClaimsPrincipal TestPrincipal(string subjectId)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", subjectId),
            new Claim(ClaimTypes.Name, "Test User")
        ], "test"));
    }

    /// <summary>
    /// Creates a test subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <returns>The test subject.</returns>
    private static WolfAuthSubject TestSubject(string subjectId)
    {
        return new WolfAuthSubject
        {
            SubjectId = subjectId,
            Provider = "default",
            ExternalUserId = subjectId
        };
    }

    /// <summary>
    /// Creates a direct permission assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="subject">The target subject.</param>
    /// <param name="permissionKey">The permission key.</param>
    /// <returns>The assignment.</returns>
    private static WolfAuthAssignment SubjectPermission(
        string assignmentId,
        WolfAuthSubject subject,
        WolfAuthPermissionKey permissionKey)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = assignmentId,
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = subject.SubjectId,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = permissionKey
        };
    }

    /// <summary>
    /// Executes an endpoint result and returns the response status code.
    /// </summary>
    /// <param name="result">The endpoint result.</param>
    /// <returns>The response status code.</returns>
    private static async Task<int> ExecuteAsync(IResult result)
    {
        using var serviceProvider = new ServiceCollection()
            .AddLogging()
            .ConfigureHttpJsonOptions(_ => { })
            .BuildServiceProvider();
        var context = new DefaultHttpContext
        {
            RequestServices = serviceProvider,
            Response =
            {
                Body = new MemoryStream()
            }
        };

        await result.ExecuteAsync(context);
        return context.Response.StatusCode;
    }

    /// <summary>
    /// Provides a deterministic subject resolver for tests.
    /// </summary>
    private sealed class TestSubjectResolver : IWolfAuthSubjectResolver
    {
        private readonly WolfAuthSubjectResolutionResult _result;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestSubjectResolver"/> class.
        /// </summary>
        /// <param name="result">The result returned by the resolver.</param>
        public TestSubjectResolver(WolfAuthSubjectResolutionResult result)
        {
            _result = result;
        }

        /// <summary>
        /// Gets the resolver call count.
        /// </summary>
        public int CallCount { get; private set; }

        /// <inheritdoc />
        public ValueTask<WolfAuthSubjectResolutionResult> ResolveAsync(
            ClaimsPrincipal principal,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            return ValueTask.FromResult(_result);
        }
    }

    /// <summary>
    /// Provides a deterministic current subject accessor for tests.
    /// </summary>
    private sealed class TestCurrentSubjectAccessor : IWolfAuthCurrentSubjectAccessor
    {
        private readonly WolfAuthSubject? _subject;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestCurrentSubjectAccessor"/> class.
        /// </summary>
        /// <param name="subject">The subject returned by the accessor.</param>
        public TestCurrentSubjectAccessor(WolfAuthSubject? subject)
        {
            _subject = subject;
        }

        /// <summary>
        /// Gets the accessor call count.
        /// </summary>
        public int CallCount { get; private set; }

        /// <inheritdoc />
        public ValueTask<WolfAuthSubject?> GetCurrentSubjectAsync(CancellationToken cancellationToken = default)
        {
            CallCount++;
            return ValueTask.FromResult(_subject);
        }
    }

    /// <summary>
    /// Provides deterministic evaluator results for tests.
    /// </summary>
    private sealed class TestEvaluator : IWolfAuthEvaluator
    {
        private readonly WolfAuthEvaluationResult _result;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestEvaluator"/> class.
        /// </summary>
        /// <param name="result">The evaluation result returned by the evaluator.</param>
        public TestEvaluator(WolfAuthEvaluationResult result)
        {
            _result = result;
        }

        /// <inheritdoc />
        public ValueTask<WolfAuthEvaluationResult> CanAsync(
            WolfAuthEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(_result);
        }

        /// <inheritdoc />
        public ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
            WolfAuthSubject subject,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(new WolfAuthEffectiveAccess { Subject = subject });
        }
    }

    /// <summary>
    /// Provides a codec that returns an unsupported parsed policy kind.
    /// </summary>
    private sealed class UnsupportedPolicyNameCodec : IWolfAuthPolicyNameCodec
    {
        /// <inheritdoc />
        public string CreatePermissionPolicyName(
            WolfAuthPermissionKey permissionKey,
            WolfAuthScopeKey? scopeKey = null)
        {
            return "unsupported";
        }

        /// <inheritdoc />
        public string CreatePolicyPolicyName(
            WolfAuthPolicyKey policyKey,
            WolfAuthScopeKey? scopeKey = null)
        {
            return "unsupported";
        }

        /// <inheritdoc />
        public bool TryParse(string policyName, out WolfAuthPolicyName parsedPolicyName)
        {
            parsedPolicyName = new WolfAuthPolicyName
            {
                Kind = WolfAuthPolicyNameKind.Unknown,
                ScopeKey = WolfAuthScopeKey.Global
            };
            return true;
        }
    }

    /// <summary>
    /// Provides all WolfAuth key types for JSON converter tests.
    /// </summary>
    private sealed class WolfAuthKeyJsonWrapper
    {
        /// <summary>
        /// Gets or sets the subject id.
        /// </summary>
        public WolfAuthSubjectId SubjectId { get; init; }

        /// <summary>
        /// Gets or sets the provider.
        /// </summary>
        public WolfAuthProviderKey Provider { get; init; }

        /// <summary>
        /// Gets or sets the external user id.
        /// </summary>
        public WolfAuthExternalUserId ExternalUserId { get; init; }

        /// <summary>
        /// Gets or sets the external group key.
        /// </summary>
        public WolfAuthExternalGroupKey ExternalGroupKey { get; init; }

        /// <summary>
        /// Gets or sets the permission key.
        /// </summary>
        public WolfAuthPermissionKey PermissionKey { get; init; }

        /// <summary>
        /// Gets or sets the role key.
        /// </summary>
        public WolfAuthRoleKey RoleKey { get; init; }

        /// <summary>
        /// Gets or sets the scope key.
        /// </summary>
        public WolfAuthScopeKey ScopeKey { get; init; }

        /// <summary>
        /// Gets or sets the policy key.
        /// </summary>
        public WolfAuthPolicyKey PolicyKey { get; init; }
    }

    /// <summary>
    /// Provides a subject key for invalid JSON converter tests.
    /// </summary>
    private sealed class WolfAuthSubjectJsonWrapper
    {
        /// <summary>
        /// Gets or sets the subject id.
        /// </summary>
        public WolfAuthSubjectId SubjectId { get; init; }
    }
}
