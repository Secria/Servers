package main

import (
	"context"
	"log"
	"net/http"
	"os"
    "secria_api/internal/auth"
	"secria_api/internal/emails"
	"secria_api/internal/middleware"
	"secria_api/internal/user"
	"time"

	"github.com/redis/go-redis/v9"
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

    log.Println("Environment: "+ENV)

    cookies_redis_client := redis.NewClient(&redis.Options{
        Addr: "redis:6379",
        Password: "",
        DB: 0,
    })
    defer cookies_redis_client.Close()

    codes_redis_client := redis.NewClient(&redis.Options{
        Addr: "redis:6379",
        Password: "",
        DB: 1,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second);
    defer cancel();
    client, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGO_URI))
    if err != nil {
        log.Panicln("Failed to connect to mongo db")
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
    auth_router.Handle("POST /login", middleware.AddJsonHeader(auth.Login(user_collection, cookies_redis_client)));
    auth_router.Handle("POST /register", auth.Register(ENV, user_collection, address_collection, CAPTCHA_SECRET));
    auth_router.Handle("GET /check", auth.CheckAuth(cookies_redis_client, user_collection));
    auth_router.HandleFunc("GET /logout", auth.Logout)


    router.Handle("/auth/", http.StripPrefix("/auth", auth_router))

    metadata_kb := 2.44
    var metadata_size int = int(metadata_kb * 1024.0)

    // /user
    required_auth_router := http.NewServeMux()
    required_auth_router.Handle("POST /address", user.AddNewAddress(user_collection, address_collection))
    //required_auth_router.Handle("POST /del_sub", user.DeleteSubaddress(user_collection, public_email_collection))
    required_auth_router.Handle("GET /generate", user.GenerateAddContactCode(codes_redis_client))
    required_auth_router.Handle("POST /contacts", user.AddContact(codes_redis_client, user_collection))
    required_auth_router.Handle("POST /tags", user.AddUserTag(user_collection))

    required_auth_router.Handle("POST /send_private", emails.SendPrivate(user_collection, metadata_collection, email_collection, &metadata_size))
    required_auth_router.Handle("POST /send_public", emails.SendPublic(user_collection, metadata_collection, email_collection))
    required_auth_router.Handle("GET /retrieve_private", emails.QueryEmails(metadata_collection, email_collection))

    required_auth_router.Handle("POST /read", emails.MarkEmailsRead(metadata_collection))
    required_auth_router.Handle("POST /star", emails.StarEmails(metadata_collection))
    required_auth_router.Handle("POST /archive", emails.ArchiveEmails(metadata_collection))
    required_auth_router.Handle("POST /delete", emails.DeleteEmails(metadata_collection))
    required_auth_router.Handle("POST /tag_email", emails.TagEmails(metadata_collection))

    router.Handle("/user/", http.StripPrefix("/user", middleware.CookieAuth(cookies_redis_client, user_collection)(required_auth_router)))

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
