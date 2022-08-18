using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;

using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using Newtonsoft.Json;
using IdentityMongo.Models;
using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using IdentityServer4.Events;
using System.Net;
using IdentityServer4.Validation;

namespace Server.Identity.Repository
{
    public class ProfileService : IProfileService
    {
        private UserManager<ApplicationUser> _userManager;
        private IMemoryCache _cache;

        public ProfileService(UserManager<ApplicationUser> userManager, IMemoryCache cache)
        {
            _userManager = userManager;
            _cache = cache;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            ApplicationUser user = await _userManager.GetUserAsync(context.Subject);
            IList<string> roles = await _userManager.GetRolesAsync(user);
            // add thông tin vào jWtToken
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("role", roles[0]));
            if (!roles.Contains("Admin"))
            {
                if (user.deviceIds == null)
                    user.deviceIds = new List<DeveiceID>();
                //xoá hết device hết hạn
                user.deviceIds.RemoveAll(x => IsExpTime(x.Exp, 0));
                await _userManager.UpdateAsync(user);
                DeveiceID deviceId = null;
                // tìm tất cả devive id chưa hết hạn trước 10 phút
                //throw new HttpStatusException(HttpStatusCode.NotFound,"this user can not have more than 20 device");
                deviceId = new DeveiceID
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
                _cache.Set(deviceIdStr, deviceIdStr,DateTimeOffset.Now.AddHours(1));

                await _userManager.UpdateAsync(user);
            }
            context.IssuedClaims.AddRange(claims);

            //await _eventService.RaiseAsync();
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            //>Processing
            ApplicationUser user = await _userManager.GetUserAsync(context.Subject);
            IList<string> roles = await _userManager.GetRolesAsync(user);
            if (!roles.Contains("Admin"))
            {
                if (user.deviceIds.FindAll(x => !IsExpTime(x.Exp, 10)).Count >= 3)
                    context.IsActive = false;
                else
                    context.IsActive = true;
            }
            else
                context.IsActive = true;

        }

        public bool IsExpTime(DateTime dateTime,int timeSpanBeforeExp)
        {
            string vnTimeZoneKey = "SE Asia Standard Time";
            TimeZoneInfo vnTimeZone = TimeZoneInfo.FindSystemTimeZoneById(vnTimeZoneKey);
            DateTime ngaygiohientai = TimeZoneInfo.ConvertTimeFromUtc(dateTime, vnTimeZone);
            TimeSpan timeSpan = new TimeSpan(0,timeSpanBeforeExp,0);
            if (DateTime.Now >= ngaygiohientai.Subtract(timeSpan))
                return true;
            return false;
        }

    }

}