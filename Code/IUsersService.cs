namespace JwtAuthentication.Code
{
    public interface IUsersService
    {
        Task<string> LoginAsync(string login, string password);
    }
}
