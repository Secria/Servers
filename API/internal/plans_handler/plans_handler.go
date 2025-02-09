package plans_handler

import (
	"shared/mongo_schemes"
)

var FreePlanOptions = mongo_schemes.UserPlanConfig{
    Plan: "free",
    Price: 0,
    SpaceLimit: 1 * 1024 * 1024 * 1024, // 4 GB
    DailyEmailLimit: 150,
    AddressLimit: 10,
    TagLimit: 30,
}
