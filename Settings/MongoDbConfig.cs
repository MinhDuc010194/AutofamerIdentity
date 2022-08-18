using System;

namespace IdentityMongo.Settings
{
    public class MongoDbConfig
    {
        public string DatabaseName { get; init; }
        public string ConnectionString { get; init; }
    }
}
