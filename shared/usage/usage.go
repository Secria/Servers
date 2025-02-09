package usage

import (
	"context"
	"shared/mongo_schemes"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetUsage(ctx context.Context, usage_collection *mongo.Collection, user_id primitive.ObjectID) (mongo_schemes.TrackedUsage, error) {
    filter := bson.D{{Key: "user_id", Value: user_id}}

    var usage mongo_schemes.TrackedUsage
    if err := usage_collection.FindOne(ctx, filter).Decode(&usage); err != nil {
        return mongo_schemes.TrackedUsage{}, err
    }

    return usage, nil
}

func IncrementUsageSize(ctx context.Context, usage_collection *mongo.Collection, users []string, increment int64) (error) {
    filter := bson.D{{Key: "email", Value: bson.M{"$in": users}}}
    update := bson.D{{Key: "$inc", Value: bson.M{"used_space": increment}}}

    _, err := usage_collection.UpdateMany(ctx, filter, update)
    return err
}

func IncrementSentUsage(ctx context.Context, usage_collection *mongo.Collection, usage_id primitive.ObjectID, increment int64) (error) {
    now := time.Now().UTC()
    next_reset := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
    update := bson.M{
        "$set": bson.M{
            "sent_emails": bson.M{
                "$cond": bson.M{
                    "if": bson.M{
                        "$gt": bson.M{
                            "reset_date": now,
                        },
                    },
                    "then": bson.M{
                        "$inc": bson.M{
                            "sent_emails": 1,
                        },
                    },
                    "else": 0,
                },
            },
            "reset_date": bson.M{
                "$cond": bson.M{
                    "if": bson.M{
                        "$gt": bson.M{
                            "reset_date": now,
                        },
                    },
                    "then": "$reset_date",
                    "else": next_reset,
                },
            },
        },
    }

    _, err := usage_collection.UpdateByID(context.TODO(), usage_id, update)
    return err
}

