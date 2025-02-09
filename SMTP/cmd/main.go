package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"shared/encryption"
	"shared/mongo_schemes"
	"shared/usage"

	"github.com/emersion/go-message"
	"github.com/emersion/go-smtp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var ENV string
var MONGO_URI string

func main() {
    ENV = os.Getenv("ENVIRONMENT")
    MONGO_URI = os.Getenv("MONGO_URI");

    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second);
    defer cancel();
    client, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGO_URI))
    if err != nil {
        log.Panicln("Failed to connect to mongo db")
    }
    db := client.Database("Secria");
    user_collection := db.Collection("Users");
    email_collection := db.Collection("Emails");
    metadata_collection := db.Collection("EmailMetadata");
    usage_collection := db.Collection("Usage")

    dh_priv, err := ecdh.P256().GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal("Failed to generate dh private key")
    }

    dh_pub := dh_priv.PublicKey().Bytes()

    backend := &Backend{
        MetadataCollection: metadata_collection,
        UserCollection: user_collection,
        EmailCollection: email_collection,
        UsageCollection: usage_collection,
        DHPrivateKey: *dh_priv,
        DHPublicKey: dh_pub,
    }

    s := smtp.NewServer(backend)

    s.Addr = ":25"
    s.Domain = "localhost"
    s.WriteTimeout = 10 * time.Second
    s.ReadTimeout = 10 * time.Second
    s.MaxMessageBytes = 1024 * 1024
    s.MaxRecipients = 50
    s.AllowInsecureAuth = true

    log.Println("Starting server at", s.Addr)
    if err := s.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
}

type Backend struct{
    MetadataCollection *mongo.Collection
    EmailCollection *mongo.Collection
    UserCollection *mongo.Collection
    UsageCollection *mongo.Collection
    DHPublicKey []byte 
    DHPrivateKey ecdh.PrivateKey
}

func (b *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
    return &Session{
        To: make([]ExtendedUser, 0),
        Backend: b,
    }, nil
}

type ExtendedUser struct {
    mongo_schemes.User
    Address string
}

type Session struct{
    From string
    FromDomain string
    To []ExtendedUser
    Backend *Backend
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
    fmt.Println("Mail from:", from)
    domain, good := extractDomain(from)
    if !good {
        return fmt.Errorf("Malformed address")
    }
    s.From = from
    s.FromDomain = domain
    return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
    filter := bson.D{{Key: "addresses", Value: to}}

    var user mongo_schemes.User
    err := s.Backend.UserCollection.FindOne(context.TODO(), filter).Decode(&user)
    if err == mongo.ErrNoDocuments {
        log.Println("RCPT user not found:", to)
        return fmt.Errorf("User not found")
    } else if err != nil {
        log.Println("Error finding rcpt user:", err.Error())
        return fmt.Errorf("Error")
    }

    s.To = append(s.To, ExtendedUser{
        User: user,
        Address: to,
    })

    return nil
}

var metadata_kb float32 = 2.44
var metadata_size = int64(metadata_kb * 1024)

func (s *Session) Data(r io.Reader) error {
    raw_headers, raw_body, err := splitCRLF(r)
    if err != nil {
        log.Println("Something failed when decoding the email", err.Error())
        return fmt.Errorf("Malformed email")
    }

    parsed_message, err := message.Read(bytes.NewReader(raw_headers))
    if err != nil {
        log.Println("Something failed when decoding the email", err.Error())
        return fmt.Errorf("Malformed email")
    }

    parsed_header := parsed_message.Header
    subject := parsed_header.Get("Subject")
    message_id := parsed_header.Get("Message-ID")
    encrypted_email, encryption_key, err := encryption.EncryptEmail(raw_body)

    email := mongo_schemes.Email{
        Encryption: mongo_schemes.Encryption_ECDH_MLKEM,
        From: s.From,
        Headers: string(raw_headers),
        Body: encrypted_email,
        DHPublicKey: s.Backend.DHPublicKey,
    }

    encoded_email, err := bson.Marshal(email)
    email_size := len(encoded_email)
    email_bson := bson.Raw(encoded_email)

    res, err := s.Backend.EmailCollection.InsertOne(context.TODO(), email_bson)
    if err != nil {
        log.Println("Error inserting email:", err.Error())
        return fmt.Errorf("Server error")
    }

    inserted_id := res.InsertedID.(primitive.ObjectID)
    estimated_size := int64(email_size) + metadata_size

    if message_id == "" {
        message_id = fmt.Sprintf("<%s@%s>", inserted_id.Hex(), s.FromDomain)
    }


    var metadata []interface{}
    var to_emails []string
    for i := range s.To {
        user := &s.To[i]

        usage, err := usage.GetUsage(context.TODO(), s.Backend.UsageCollection, user.Id)
        if err != nil {
        }
        
        if usage.UsedSpace < user.PlanConfig.SpaceLimit {
            to_emails = append(to_emails, user.MainEmail)
            ev, err := encryption.GenerateEncryptedKey(encryption_key, s.Backend.DHPrivateKey, &user.User)
            if err != nil {
                log.Println("Something failed when encrypting the email", err.Error())
                return fmt.Errorf("There was an error encrypting the emails")
            }

            m := mongo_schemes.Metadata{
                Size: estimated_size,
                KeyUsed: ev.UsedKey,
                UsedAddress: user.Address,
                EmailID: inserted_id,
                MessageId: message_id,
                Subject: subject,
                From: s.From,
                Ciphertext: ev.CipherText,
                EncryptedKey: ev.SecondStageKey,
                Private: false,
            }

            metadata = append(metadata, m)
        }
    }

    _, err = s.Backend.MetadataCollection.InsertMany(context.TODO(), metadata)
    if err != nil {
        log.Println("Error inserting metadata:", err.Error())
        return fmt.Errorf("Server error")
    }

    err = usage.IncrementUsageSize(context.TODO(), s.Backend.UsageCollection, to_emails, estimated_size)
    if err != nil {
        log.Println("Error updating used size:", err.Error())
        return fmt.Errorf("Server error")
    }

    return nil
}

func (s *Session) Reset() {
    s.From = ""
    s.To = []ExtendedUser{}
}

func (s *Session) Logout() error {
    return nil
}

func extractDomain(address string) (string, bool) {
    parts := strings.Split(address, "@")
    if len(parts) != 2 {
        return "", false
    }
    return parts[1], true
}

const separator = "\r\n\r\n"

func splitCRLF(r io.Reader) ([]byte, []byte, error) {
    raw, err := io.ReadAll(r)
    if err != nil {
        return nil, nil, err
    }

    splitIndex := bytes.Index(raw, []byte(separator))
    if splitIndex == -1 {
        return nil, nil, fmt.Errorf("Malformed email")
    }


    header := raw[:splitIndex]
    body := raw[splitIndex+4:]
    return header, body, nil
}
