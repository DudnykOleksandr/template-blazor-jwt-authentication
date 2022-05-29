using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;

namespace JwtAuthentication.Code;

public class CustomBlazorAuthStateProvider : AuthenticationStateProvider
{
    private readonly BlazorAppLoginService blazorAppLoginService;

    public CustomBlazorAuthStateProvider(BlazorAppLoginService blazorAppLoginService)
    {
        this.blazorAppLoginService = blazorAppLoginService;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var claims = await blazorAppLoginService.GetLoginInfoAsync();
        ClaimsIdentity claimsIdentity;
        if (claims.Any())
        {
            claimsIdentity = new ClaimsIdentity(claims, "Bearer");
        }
        else
        {
            claimsIdentity = new ClaimsIdentity();
        }
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
        return new AuthenticationState(claimsPrincipal);
    }
}