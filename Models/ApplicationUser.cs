using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;
using System;

namespace IdentityMongo.Models
{
    [CollectionName("Users")]
    public class ApplicationUser : MongoIdentityUser<Guid>
    {
        public List<DeveiceID> deviceIds { get; set; }
        public List<Lisence_key> lisence_Keys { get; set; }
    }

    public class DeviceToken
    {
        public string token { get; set; }
        public DateTime  Exp  { get; set; }
    }

    public class DeveiceID
    {
        public string id { get; set; }
        public DeviceToken deviceToken { get; set; }
        public DateTime Exp { get; set; }
    }

    public class Lisence_key
    {
        public string key { get; set; }
        public int max_device { get; set; }
    }
}
