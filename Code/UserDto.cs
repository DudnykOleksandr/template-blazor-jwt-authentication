using System.Text.Json.Serialization;

namespace JwtAuthentication.Code;

public static class Extensions
{
    public static List<UserRoles> FromFlagsToList(this UserRoles userRoles)
    {
        var result = new List<UserRoles>();
        foreach (UserRoles userRole in Enum.GetValues(typeof(UserRoles)))
        {
            if (userRole == UserRoles.None)
            {
                continue;
            }

            if (userRoles.HasFlag(userRole))
            {
                result.Add(userRole);
            }
        }

        return result;
    }
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum UserRoles
{
    None = 0,
    Admin = 1,
    RegularUser = 2
}

public static class UserRolesNames
{
    public const string Admin = "admin";
    public const string RegularUser = "regularuser";
}


public class UserDto
{
    public long Id { get; set; }

    public string Login { get; set; }

    public string Password { get; set; }

    public UserRoles Roles { get; set; }
}