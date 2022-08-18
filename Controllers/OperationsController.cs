using IdentityMongo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System;
using Microsoft.AspNetCore.Authorization;
using IdentityServer4.Configuration;
using IdentityServer4.Services;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Identity.Model;
using IdentityServer4;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using Identity.Models.DTO;

namespace IdentityMongo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : Controller
    {
        private UserManager<ApplicationUser> userManager;
        private RoleManager<ApplicationRole> roleManager;
        private IMemoryCache _cache;

        public UserController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, IMemoryCache cache)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _cache = cache;
        }

        [HttpPost("User")]
        public async Task<IActionResult> Create(User user)
        {
                ApplicationUser appUser = new ApplicationUser
                {
                    UserName = user.Name,
                    Email = user.Email
                };

                IdentityResult result = await userManager.CreateAsync(appUser, user.Password);

                //Adding User to User Role
                await userManager.AddToRoleAsync(appUser, "User");

                if (result.Succeeded)
                    return Ok(user); 
                else
                {
                    return BadRequest(result.Errors);
                }          
        }

        [HttpPost("Admin")]
        public async Task<IActionResult> CreateAdmin(User user)
        {
            ApplicationUser appUser = new ApplicationUser
            {
                UserName = user.Name,
                Email = user.Email
            };

            IdentityResult result = await userManager.CreateAsync(appUser, user.Password);

            //Adding User to Admin Role
            await userManager.AddToRoleAsync(appUser, "Admin");

            if (result.Succeeded)
                return Ok(user);
            else
            {
                return BadRequest(result.Errors);
            }
        }

        [HttpPost("role")]
        public async Task<IActionResult> CreateRole([Required] string name)
        {
                IdentityResult result = await roleManager.CreateAsync(new ApplicationRole() { Name = name });
                if (result.Succeeded)
                    return Ok("Role Created Successfully");
                else
                {
                return BadRequest(result.Errors);
            }
        }

        [HttpPost("add-lisense")]
        public async Task<IActionResult> CreateLisense([Required] [FromBody] UserLisenseDTO userDto)
        {
            var user = await userManager.FindByNameAsync(userDto.user_name);
            Lisence_key key = new Lisence_key() { key = RandomString(20), max_device = userDto.maxDevice };
            if (user.lisence_Keys == null)
                user.lisence_Keys = new List<Lisence_key>();
            user.lisence_Keys.Add(key);
            IdentityResult result = await userManager.UpdateAsync(user);
            if (result.Succeeded)
                return Ok(new {key = key, desc = "Lisense Created Successfully" });
            else
            {
                return BadRequest(result.Errors);
            }
        }

        [HttpPost("loginas")]
        public async Task<IActionResult> LoginAs([FromBody]UserLoginDTO userDto, [FromServices] ITokenService TS,
    [FromServices] IUserClaimsPrincipalFactory<ApplicationUser> principalFactory,
    [FromServices] IdentityServerOptions options)
        {
            var Request = new TokenCreationRequest();
            var user = await userManager.FindByNameAsync(userDto.user_name);
            IList<string> roles = await userManager.GetRolesAsync(user);
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("role", roles[0]));
            if (!roles.Contains("Admin"))
            {
                if (user.deviceIds == null)
                    user.deviceIds = new List<DeveiceID>();
                //xoá hết device hết hạn
                user.deviceIds.RemoveAll(x => IsExpTime(x.Exp, 0));
                if(string.IsNullOrEmpty(userDto.license_key) || !user.lisence_Keys.Any(x => x.key.Equals(userDto.license_key)))
                    return BadRequest("license key is incorect");
                Lisence_key key = user.lisence_Keys.Find(x => x.key.Equals(userDto.license_key));
                if (user.deviceIds.FindAll(x => !IsExpTime(x.Exp, 10)).Count >= 30)
                    return BadRequest("this user can not have more than 20 device");
                //throw new HttpStatusException(HttpStatusCode.NotFound,"this user can not have more than 20 device");
                DeveiceID deviceId = new DeveiceID
                {
                    id = Guid.NewGuid().ToString("d").Substring(1, 15),
                    Exp = DateTime.Now.AddHours(1),
                    deviceToken = new DeviceToken()
                    {
                        Exp = DateTime.Now.AddMinutes(30),
                        token = Guid.NewGuid().ToString("d").Substring(1, 15)
                    }
                };
                string deviceIdStr = deviceId.id;
                user.deviceIds.Add(deviceId);

                claims.Add(new Claim("device-id", deviceIdStr));
                claims.Add(new Claim("device-token", deviceId.deviceToken.token));
                _cache.Set(deviceIdStr, deviceIdStr, DateTimeOffset.Now.AddHours(1));

                await userManager.UpdateAsync(user);
            }

            var TokenValue = await GenarateToken(TS, principalFactory, options, user);
            return Ok(TokenValue); 
        }

        private bool IsExpTime(DateTime dateTime, int timeSpanBeforeExp)
        {
            string vnTimeZoneKey = "SE Asia Standard Time";
            TimeZoneInfo vnTimeZone = TimeZoneInfo.FindSystemTimeZoneById(vnTimeZoneKey);
            DateTime ngaygiohientai = TimeZoneInfo.ConvertTimeFromUtc(dateTime, vnTimeZone);
            TimeSpan timeSpan = new TimeSpan(0, timeSpanBeforeExp, 0);
            if (DateTime.Now >= ngaygiohientai.Subtract(timeSpan))
                return true;
            return false;
        }

        private async Task<string> GenarateToken([FromServices] ITokenService TS,
    [FromServices] IUserClaimsPrincipalFactory<ApplicationUser> principalFactory,
    [FromServices] IdentityServerOptions options,ApplicationUser user)
        {
            var Request = new TokenCreationRequest();
            var IdentityPricipal = await principalFactory.CreateAsync(user);
            var IdentityUser = new IdentityServerUser(user.Id.ToString());
            IdentityUser.AdditionalClaims = IdentityPricipal.Claims.ToArray();
            IdentityUser.DisplayName = user.UserName;
            IdentityUser.AuthenticationTime = System.DateTime.UtcNow;
            IdentityUser.IdentityProvider = IdentityServerConstants.LocalIdentityProvider;
            Request.Subject = IdentityUser.CreatePrincipal();
            Request.IncludeAllIdentityClaims = true;
            Request.ValidatedRequest = new ValidatedRequest();
            Request.ValidatedRequest.Subject = Request.Subject;
            Request.ValidatedRequest.SetClient(IdentityConfiguration.Clients.First());
            Request.ValidatedResources = new ResourceValidationResult(new Resources() { IdentityResources = IdentityConfiguration.IdentityResources.ToList(), ApiScopes = IdentityConfiguration.ApiScopes.ToList() });
            Request.ValidatedRequest.Options = options;
            Request.ValidatedRequest.ClientClaims = IdentityUser.AdditionalClaims;
            var Token = await TS.CreateAccessTokenAsync(Request);
            Token.Issuer = HttpContext.Request.Scheme + "://" + HttpContext.Request.Host.Value;
            return await TS.CreateSecurityTokenAsync(Token);
        }

        private string RandomString(int length)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[length];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            return new String(stringChars);
        }
    }
}
