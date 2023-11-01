using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using System.Security.Claims;

namespace BlazorAuth;

public class CookieAuthStateProvider : RevalidatingServerAuthenticationStateProvider
{
    public CookieAuthStateProvider(ILoggerFactory loggerFactory): base(loggerFactory)
    {

    }

    protected override TimeSpan RevalidationInterval => TimeSpan.FromSeconds(10);

    protected override Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        var result = false;
        var user = authenticationState?.User;

        if(user?.Identity?.IsAuthenticated ?? false) 
        {
            var expiryDTClaim = user.Claims.Where(c => c.Type == ClaimTypes.Expiration).FirstOrDefault();
            var expiryDTValue = expiryDTClaim?.Value ?? "";

            if(!string.IsNullOrEmpty(expiryDTValue))
            {
                if(DateTimeOffset.TryParse(expiryDTValue, out DateTimeOffset expiryDT))
                {
                    if(expiryDT > DateTimeOffset.UtcNow)
                    {
                        result = true;
                    }
                }
            }
        }

        return Task.FromResult(result);
    }
}
