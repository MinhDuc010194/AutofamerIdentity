using IdentityServer4;
using IdentityServer4.Models;

namespace Identity.Model
{
    public class IdentityConfiguration
    {
        private static string[] allowedScopes =
{
            IdentityServerConstants.StandardScopes.OfflineAccess,
            IdentityServerConstants.StandardScopes.OpenId,
            "adminApi"
        };

        public static IEnumerable<IdentityResource> IdentityResources =>
           new IdentityResource[]
           {
               new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
           };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope("adminApi"),
            };

        public static IEnumerable<Client> Clients =>
            new Client[]
            {
                new Client
                {
                    ClientId = "admin_autofarmer",
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                    AllowOfflineAccess = true,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    UpdateAccessTokenClaimsOnRefresh = true,
                    RefreshTokenExpiration = TokenExpiration.Sliding,
                    AllowAccessTokensViaBrowser = true,
                    AccessTokenLifetime = 15*60, // minutes
                    ClientSecrets = { new Secret("K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=".Sha256()) },
                    AllowedScopes = allowedScopes,
                }
            };


    }
}
