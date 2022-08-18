using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Memory;

namespace Identity.Services
{
    public class DeviceTokenRequirement : IAuthorizationRequirement
    {
        public DeviceTokenRequirement()
        {
        }
    }

    public class DeviceTokenRequirementHandler :
              AuthorizationHandler<DeviceTokenRequirement>
    {
        private IMemoryCache _cache;
        public DeviceTokenRequirementHandler(IMemoryCache cache)
        {
            _cache = cache;
        }
        protected override Task HandleRequirementAsync(
               AuthorizationHandlerContext context,
               DeviceTokenRequirement requirement)
        {
            var user = context.User;
            var claimDeviceId = context.User.FindFirst("device-id");
            var claimDeviceToken = context.User.FindFirst("device-token");
            if (claimDeviceId != null && claimDeviceToken != null)
            {
                string deviceToken = _cache.Get<string>(claimDeviceId.Value);
                if (deviceToken != null)
                    //kiểm tra trong cache có tồn tại value với key DeviceId = claimDeviceToken trong token
                    context.Succeed(requirement);
                //context.Fail();

            }
            return Task.CompletedTask;
        }
    }
}

