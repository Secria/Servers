package plans_handler

import "shared/mongo_schemes"

var FreePlanOptions = mongo_schemes.UserPlansConfig{
    Plan: "free",
    Price: 0,
    SpaceLimit: 4*1024*1024, // 4 GB
    DailyEmailLimit: 100,
    AddressLimit: 3,
    TagLimit: 3,
}
