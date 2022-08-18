using System;
using IdentityMongo.Models;

namespace Identity.Models.DTO
{
    public class UserLoginDTO
    {
        public string user_name { get; set; }
        public string license_key { get; set; }
    }

    public class UserLisenseDTO
    {
        public string user_name { get; set; }
        public int maxDevice { get; set; }
    }
}

