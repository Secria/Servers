package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"secria_api/internal/auth"
	"secria_api/internal/emails"
	"secria_api/internal/middleware"
	"secria_api/internal/totp"
	"secria_api/internal/user"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var CORS_HEADER string
var DOMAIN string
var ENV string
var MONGO_URI string
var REDIS_HOST string
var CAPTCHA_SECRET string

func main() {
    ENV = os.Getenv("ENVIRONMENT")
    MONGO_URI = os.Getenv("MONGO_URI");
    CAPTCHA_SECRET = os.Getenv("CAPTCHA_SECRET")

    if ENV == "DEV" {
        CORS_HEADER = "http://localhost:8080"
        DOMAIN = "localhost:8000"
    }

    log.Println("Environment:", ENV)

    redis_address := "redis:6379"
    redis_password := ""
    cookies_redis_client := redis.NewClient(&redis.Options{
        Addr: redis_address,
        Password: redis_password,
        DB: 0,
    })
    defer cookies_redis_client.Close()

    share_codes_redis_client := redis.NewClient(&redis.Options{
        Addr: redis_address,
        Password: redis_password,
        DB: 1,
    })

    generate_totp_codes_redis_client := redis.NewClient(&redis.Options{
        Addr: redis_address,
        Password: redis_password,
        DB: 2,
    })

    mfa_attempt_redis_client := redis.NewClient(&redis.Options{
        Addr: redis_address,
        Password: redis_password,
        DB: 3,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second);
    defer cancel();
    client, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGO_URI))
    if err != nil {
        log.Panicln("Failed to connect to mongo db")
    }

    if ENV == "DEV" {
        initializeDB(context.TODO(), client)
    }

    db := client.Database("Secria");
    user_collection := db.Collection("Users");
    address_collection := db.Collection("Addresses")
    email_collection := db.Collection("Emails");
    metadata_collection := db.Collection("EmailMetadata");

    //cleanup_emails := emails.CleanupEmails(email_collection, 100)
    router := http.NewServeMux()

    // /auth
    auth_router := http.NewServeMux()
    auth_router.Handle("POST /login", middleware.AddJsonHeader(auth.Login(user_collection, cookies_redis_client, mfa_attempt_redis_client)));
    auth_router.Handle("POST /mfa", totp.LoginCheckTOTP(cookies_redis_client, mfa_attempt_redis_client, user_collection))
    auth_router.Handle("POST /register", auth.Register(ENV, user_collection, address_collection, CAPTCHA_SECRET));
    auth_router.Handle("GET /check", auth.CheckAuth(cookies_redis_client, user_collection));
    auth_router.HandleFunc("GET /logout", auth.Logout)


    router.Handle("/auth/", http.StripPrefix("/auth", auth_router))

    metadata_kb := 2.44
    var metadata_size int = int(metadata_kb * 1024.0)

    // /user
    required_auth_router := http.NewServeMux()
    required_auth_router.Handle("POST /address", user.AddNewAddress(user_collection, address_collection))
    required_auth_router.Handle("POST /delete_address", user.DeleteAddress(user_collection, address_collection))
    required_auth_router.Handle("POST /rotate", user.RotateAddress(user_collection, address_collection))
    required_auth_router.Handle("GET /generate", user.GenerateAddContactCode(share_codes_redis_client))
    required_auth_router.Handle("POST /contacts", user.AddContact(share_codes_redis_client, user_collection))
    required_auth_router.Handle("POST /tags", user.AddUserTag(user_collection))

    required_auth_router.Handle("POST /send_private", emails.SendPrivate(user_collection, metadata_collection, email_collection, &metadata_size))
    required_auth_router.Handle("POST /send_public", emails.SendPublic(user_collection, metadata_collection, email_collection))
    required_auth_router.Handle("GET /query", emails.QueryEmails(metadata_collection, email_collection))

    required_auth_router.Handle("POST /read", emails.MarkEmailsRead(metadata_collection))
    required_auth_router.Handle("POST /star", emails.StarEmails(metadata_collection))
    required_auth_router.Handle("POST /archive", emails.ArchiveEmails(metadata_collection))
    required_auth_router.Handle("POST /delete", emails.DeleteEmails(metadata_collection))
    required_auth_router.Handle("POST /tag_email", emails.TagEmails(metadata_collection))

    router.Handle("/user/", http.StripPrefix("/user", middleware.CookieAuth(cookies_redis_client, user_collection)(required_auth_router)))

    totp_router := http.NewServeMux()

    totp_router.Handle("GET /generate", totp.GenerateTOTP(generate_totp_codes_redis_client))
    totp_router.Handle("POST /disable", totp.DisableTOTP(user_collection))
    totp_router.Handle("POST /initial", totp.InitialValidateTOTP(generate_totp_codes_redis_client, user_collection))

    router.Handle("/otp/", http.StripPrefix("/otp", middleware.CookieAuth(cookies_redis_client, user_collection)(totp_router)))

    shared_middleware := middleware.CreateStack(
        middleware.Logging,
        middleware.AddJsonHeader,
        middleware.CorsMiddleware(CORS_HEADER),
    )

    server := http.Server {
        Addr: ":8000",
        Handler: shared_middleware(router),
    }
    log.Println("Starting server on port :8000")
    server.ListenAndServe();
}

func initializeDB(ctx context.Context, client *mongo.Client) {
    databases, err := client.ListDatabases(ctx, bson.D{}) 
    if err != nil {
        log.Fatal("Couldn't retrieve databases: ", err.Error())
    }

    for _, d := range databases.Databases {
        if d.Name == "Secria" {
            return
        }
    }

    db := client.Database("Secria")
    err = db.CreateCollection(ctx, "Users")
    if err != nil {
        log.Fatal("Couldn't create collection", err.Error())
    }
    err = db.CreateCollection(ctx, "Addresses")
    if err != nil {
        log.Fatal("Couldn't create collection", err.Error())
    }
    err = db.CreateCollection(ctx, "Emails")
    if err != nil {
        log.Fatal("Couldn't create collection", err.Error())
    }
    err = db.CreateCollection(ctx, "Metadata")
    if err != nil {
        log.Fatal("Couldn't create collection", err.Error())
    }

    address_collection := db.Collection("Addresses")
    value := true
    address_index := mongo.IndexModel{
        Keys: bson.D{{Key: "address", Value: 1}},
        Options: &options.IndexOptions{
            Unique: &value,
        },
    }
    _, err = address_collection.Indexes().CreateOne(ctx, address_index)
    if err != nil {
        log.Fatal("Couldn't index the collection", err.Error())
    }

    metadata_collection := db.Collection("EmailMetadata")
    metadata_indices := []mongo.IndexModel{
        {
            Keys: bson.D{{Key: "used_address", Value: 1}},
        },
        {
            Keys: bson.D{{Key: "message_id", Value: 1}},
        },
        {
            Keys: bson.D{{Key: "subject", Value: "text"}, {Key: "from", Value: "text"}},
        },
    }
    _, err = metadata_collection.Indexes().CreateMany(ctx, metadata_indices)

    if err != nil {
        log.Fatal("Couldn't index the collection", err.Error())
    }
}
