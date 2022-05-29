using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.Extensions.Configuration;

namespace JwtAuthentication.Code;

public class BlazorAppLoginService
{
    private readonly string TokenKey = nameof(TokenKey);

    private readonly ProtectedLocalStorage localStorage;
    private readonly NavigationManager navigation;
    private readonly IUsersService usersService;
    private readonly IConfiguration configuration;

    public BlazorAppLoginService(ProtectedLocalStorage localStorage, NavigationManager navigation, IUsersService usersService, IConfiguration configuration)
    {
        this.localStorage = localStorage;
        this.navigation = navigation;
        this.usersService = usersService;
        this.configuration = configuration;
    }

    public async Task<bool> LoginAsync(string userName, string password)
    {
        var isSuccess = false;

        var token = await usersService.LoginAsync(userName, password);
        if (!string.IsNullOrEmpty(token))
        {
            isSuccess = true;
            await localStorage.SetAsync(TokenKey, token);
        }

        return isSuccess;
    }


    public async Task<List<Claim>> GetLoginInfoAsync()
    {
        var emptyResut = new List<Claim>();
        ProtectedBrowserStorageResult<string> token = default;
        try
        {
            token = await localStorage.GetAsync<string>(TokenKey);
        }
        catch (CryptographicException)
        {
            await LogoutAsync();
            return emptyResut;
        }

        if (token.Success && token.Value != default)
        {
            var claims = JwtTokenHelper.ValidateDecodeToken(token.Value, configuration);
            if (!claims.Any())
            {
                await LogoutAsync();
            }
            return claims;
        }
        return emptyResut;
    }

    public async Task LogoutAsync()
    {
        await RemoveAuthDataFromStorageAsync();
        navigation.NavigateTo("/", true);
    }


    private async Task RemoveAuthDataFromStorageAsync()
    {
        await localStorage.DeleteAsync(TokenKey);
    }
}