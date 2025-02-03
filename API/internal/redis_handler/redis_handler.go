package redis_handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

    "shared/mongo_schemes"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type CookieObject struct {
    UserId primitive.ObjectID `json:"user_id"`
    RefreshDate int64 `json:"refresh_date"`
    NoRefresh bool `json:"no_refresh,omitempty"`
}

func GetCookieObject(redis_client *redis.Client, cookie_value string) (CookieObject, error) {
    cookie_string, err := redis_client.Get(context.Background(), cookie_value).Result()
    if err != nil {
        log.Println("Failed to get session cookie: ", err.Error())
        return CookieObject{}, err
    }

    var cookie_object CookieObject
    err = json.Unmarshal([]byte(cookie_string), &cookie_object)
    if err != nil {
        log.Println("Failed to get session cookie: ", err.Error())
        return CookieObject{}, err
    }
    
    return cookie_object, nil
}

func GetUserFromCookie(user_collection *mongo.Collection, cookie_object CookieObject) (mongo_schemes.User, error) {
    user_id := cookie_object.UserId

    filter := bson.M{ "_id": user_id}
    var user mongo_schemes.User
    err := user_collection.FindOne(context.Background(), filter).Decode(&user)
    if err != nil {
        log.Println("Failed find session cookie user: "+err.Error())
        return mongo_schemes.User{}, err
    }
    
    return user, nil
}

func GenerateCookie(redis_client *redis.Client, user_id primitive.ObjectID) (http.Cookie, error) {
    new_cookie := CookieObject{
        UserId: user_id,
        RefreshDate: time.Now().Add(time.Hour * 2).Unix(),
    }
    new_cookie_json, err := json.Marshal(new_cookie)
    if err != nil {
        log.Println("Failed to serialize new cookie: "+err.Error())
        return http.Cookie{}, err
    }

    uuid := uuid.New().String()
    err = redis_client.Set(context.Background(), uuid, new_cookie_json, time.Hour*24*7).Err()
    if err != nil {
        log.Println("Failed to store new cookie: "+err.Error())
        return http.Cookie{}, err
    }


    cookie := http.Cookie{
        Name: "session",
        Value: uuid,
        HttpOnly: true,
        Secure: true,
        SameSite: http.SameSiteLaxMode,
        Path: "/",
        //Domain: DOMAIN,
    }

    return cookie, nil
}

func RegenerateCookie(redis_client *redis.Client, old_cookie_name string, old_cookie_object CookieObject) (http.Cookie, error) {
    cookie, err := GenerateCookie(redis_client, old_cookie_object.UserId)
    if err != nil {
        log.Println("Failed to generate new cookie: "+err.Error())
        return http.Cookie{}, err
    }

    old_cookie_object.NoRefresh = true
    old_cookie_json, err := json.Marshal(old_cookie_object)
    if err != nil {
        log.Println("Failed to serialize old cookie: "+err.Error())
        return http.Cookie{}, err
    }

    err = redis_client.Set(context.Background(), old_cookie_name, old_cookie_json, time.Minute * 5).Err()
    if err != nil {
        log.Println("Failed to modify old cookie ttl: "+err.Error())
        return http.Cookie{}, err
    }

    return cookie, nil
}

func GenerateShareCode(redis_client *redis.Client, user primitive.ObjectID) (string, error) {
    uuid := uuid.New().String()
    err := redis_client.Set(context.Background(), uuid, user.Hex(), time.Hour).Err()
    return uuid, err
}

func GetUserFromSharedCode(redis_client *redis.Client, user_collection *mongo.Collection, shared_code string) (mongo_schemes.User, error) {
    user_id_string, err := redis_client.Get(context.Background(), shared_code).Result()
    if err != nil {
        return mongo_schemes.User{}, err
    }

    err = redis_client.Del(context.TODO(), shared_code).Err()
    if err != nil {
        return mongo_schemes.User{}, err
    }

    user_id, err := primitive.ObjectIDFromHex(user_id_string)
    if err != nil {
        return mongo_schemes.User{}, err
    }

    filter := bson.D{{Key: "_id", Value: user_id}}
    
    var user mongo_schemes.User
    err = user_collection.FindOne(context.TODO(), filter).Decode(&user)
    if err != nil {
        return mongo_schemes.User{}, err
    }

    return user, nil
}
