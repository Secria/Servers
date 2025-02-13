package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	attachment "secria_api/internal"
	"secria_api/internal/auth"
	"secria_api/internal/emails"
	"secria_api/internal/middleware"
	"secria_api/internal/proxy"
	"secria_api/internal/totp"
	"secria_api/internal/user"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func CreateBucket(client *minio.Client) {
    err := client.MakeBucket(context.TODO(), BUCKET_NAME, minio.MakeBucketOptions{Region: REGION})
    if err != nil {
        exists, errBucketExists := client.BucketExists(context.TODO(), BUCKET_NAME)
        if errBucketExists == nil && exists {
            log.Println("We already own", BUCKET_NAME)
        } else {
            log.Fatalln(err)
        }
    }
    fmt.Println("Bucket created: ", BUCKET_NAME)
}


var CORS_HEADER string
var DOMAIN string
var ENV string
var MONGO_URI string
var REDIS_HOST string
var CAPTCHA_SECRET string
var S3_ENDPOINT string
var ACCESS_KEY_ID string
var SECRET_ACCESS_KEY string
var BUCKET_NAME string
var REGION string

func main() {
    ENV = os.Getenv("ENVIRONMENT")
    MONGO_URI = os.Getenv("MONGO_URI");
    CAPTCHA_SECRET = os.Getenv("CAPTCHA_SECRET")
    S3_ENDPOINT = os.Getenv("S3_ENDPOINT")
    ACCESS_KEY_ID = os.Getenv("ACCESS_KEY_ID")
    SECRET_ACCESS_KEY = os.Getenv("SECRET_ACCESS_KEY")
    BUCKET_NAME = os.Getenv("BUCKET_NAME")
    REGION = os.Getenv("REGION")

    if ENV == "DEV" {
        CORS_HEADER = "http://localhost:8080"
        DOMAIN = "localhost:8000"
    }

    log.Println("Environment:", ENV)

    minio_client, err := minio.New(S3_ENDPOINT, &minio.Options{
        Creds: credentials.NewStaticV4(ACCESS_KEY_ID, SECRET_ACCESS_KEY, ""),
        Secure: false,
    })
    if err != nil {
        log.Fatalln(err)
    }

    CreateBucket(minio_client)


    redis_address := "redis:6379"
    redis_password := ""
    redis_client := redis.NewClient(&redis.Options{
        Addr: redis_address,
        Password: redis_password,
        DB: 0,
    })
    defer redis_client.Close()

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
    email_collection := db.Collection("Emails");
    metadata_collection := db.Collection("EmailMetadata");
    usage_collection := db.Collection("Usage")

    shared_middleware := middleware.CreateStack(
        middleware.Logging,
        middleware.CorsMiddleware(CORS_HEADER),
    )

    json_middleware := middleware.AddJsonHeader

    cookie_middleware := middleware.CookieAuth(redis_client, user_collection)

    router := http.NewServeMux()

    // /auth
    auth_router := http.NewServeMux()
    auth_router.Handle("POST /login", auth.Login(user_collection, redis_client))
    // auth_router.Handle("POST /mfa", totp.LoginCheckTOTP(redis_client, user_collection))
    auth_router.Handle("POST /register", auth.Register(ENV, user_collection, usage_collection, CAPTCHA_SECRET))
    auth_router.Handle("GET /check", auth.CheckAuth(redis_client, user_collection))
    auth_router.HandleFunc("GET /logout", auth.Logout)


    router.Handle("/auth/", http.StripPrefix("/auth", json_middleware(auth_router)))

    metadata_kb := 2.44
    var metadata_size = int64(metadata_kb * 1024.0)
    // /user
    required_auth_router := http.NewServeMux()
    required_auth_router.Handle("POST /address", user.AddNewAddress(user_collection))
    required_auth_router.Handle("POST /delete_address", user.DeleteAddress(user_collection))
    required_auth_router.Handle("POST /rotate", user.RotateAddress(user_collection))
    required_auth_router.Handle("GET /generate", user.GenerateAddContactCode(redis_client))
    required_auth_router.Handle("POST /contacts", user.AddContact(redis_client, user_collection))
    required_auth_router.Handle("POST /delete_contacts", user.DeleteContact(user_collection))
    required_auth_router.Handle("POST /tags", user.AddUserTag(user_collection))
    required_auth_router.Handle("POST /delete_tag", user.DeleteUserTag(user_collection, metadata_collection))

    required_auth_router.Handle("POST /keys", user.GetAddressInfo(user_collection))
    required_auth_router.Handle("POST /send_private", emails.SendEmail(user_collection, metadata_collection, email_collection, usage_collection, &metadata_size))
    required_auth_router.Handle("POST /draft", emails.StoreDraft(user_collection, metadata_collection, email_collection, usage_collection, &metadata_size))
    required_auth_router.Handle("POST /empty", emails.CreateEmptyDraft(metadata_collection, email_collection, usage_collection))
    required_auth_router.Handle("POST /upload", emails.UploadFile(minio_client, BUCKET_NAME, metadata_collection, email_collection, usage_collection))
    //required_auth_router.Handle("POST /send_public", emails.SendPublic(user_collection, metadata_collection, email_collection))
    required_auth_router.Handle("GET /query", emails.QueryEmails(metadata_collection, email_collection))

    required_auth_router.Handle("POST /read", emails.MarkEmailsRead(metadata_collection))
    required_auth_router.Handle("POST /star", emails.StarEmails(metadata_collection))
    required_auth_router.Handle("POST /archive", emails.ArchiveEmails(metadata_collection))
    required_auth_router.Handle("POST /delete", emails.DeleteEmails(metadata_collection))
    required_auth_router.Handle("POST /restore", emails.RestoreEmails(metadata_collection))
    required_auth_router.Handle("POST /tag_email", emails.TagEmails(metadata_collection))

    router.Handle("/user/", http.StripPrefix("/user", cookie_middleware(required_auth_router)))

    totp_router := http.NewServeMux()

    totp_router.Handle("GET /generate", totp.GenerateTOTP(redis_client))
    totp_router.Handle("POST /disable", totp.DisableTOTP(user_collection))
    totp_router.Handle("POST /initial", totp.InitialValidateTOTP(redis_client, user_collection))

    router.Handle("/otp/", http.StripPrefix("/otp", json_middleware(cookie_middleware(totp_router))))

    image_router := http.NewServeMux()

    image_router.HandleFunc("GET /image", proxy.ImageProxy)

    router.Handle("/proxy/", http.StripPrefix("/proxy", middleware.CookieAuth(redis_client, user_collection)(image_router)))

    router.Handle("GET /attachment", attachment.DownloadAttachment(minio_client, BUCKET_NAME))

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
    err = db.CreateCollection(ctx, "EncryptionMetadata")
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

    encryption_collection := db.Collection("EncryptionMetadata")
    encryption_index := mongo.IndexModel{
        Keys: bson.D{
            {Key: "from", Value: 1}, 
            {Key: "to", Value: 1}},
    }
    _, err = encryption_collection.Indexes().CreateOne(ctx, encryption_index)
    if err != nil {
        log.Fatal("Couldn't index the collection", err.Error())
    }

    user_collection := db.Collection("Users")
    user_index := mongo.IndexModel{
        Keys: bson.D{{Key: "addressess", Value: 1}},
    }
    _, err = user_collection.Indexes().CreateOne(ctx, user_index)
    if err != nil {
        log.Fatal("Couldn't index the collection", err.Error())
    }

    usage_collection := db.Collection("Usage")
    usage_index := mongo.IndexModel{
        Keys: bson.D{{Key: "email", Value: 1}},
    }
    _, err = usage_collection.Indexes().CreateOne(ctx, usage_index)
    if err != nil {
        log.Fatal("Couldn't index the collection", err.Error())
    }
}
