package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"shared/encryption"
	"shared/mongo_schemes"

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

    dh_priv, err := ecdh.P256().GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal("Failed to generate dh private key")
    }

    dh_pub := dh_priv.PublicKey().Bytes()
    encoded_dh_pub := base64.StdEncoding.EncodeToString(dh_pub)

    backend := &Backend{
        MetadataCollection: metadata_collection,
        UserCollection: user_collection,
        EmailCollection: email_collection,
        DHPrivateKey: *dh_priv,
        DHPublicKey: encoded_dh_pub,
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
    DHPublicKey string
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
    Subaddress string
}

type Session struct{
    From string
    To []ExtendedUser
    Backend *Backend
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
    fmt.Println("Mail from:", from)
    s.From = from
    return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
    user_domain := strings.Split(to, "@")
    if len(user_domain) != 2 {
        return fmt.Errorf("Malformed address")
    }

    user_key := strings.Split(user_domain[0], "+")
    if len(user_key) != 2 {
        return fmt.Errorf("You have to send the message to a subaddress")
    }

    email := user_key[0] + "@" + user_domain[1]

    filter := bson.D{{Key: "email", Value: email}}

    var user mongo_schemes.User
    err := s.Backend.UserCollection.FindOne(context.TODO(), filter).Decode(&user)
    if err == mongo.ErrNoDocuments {
        log.Println("RCPT user not found:", email)
        return fmt.Errorf("User not found")
    } else if err != nil {
        log.Println("Error finding rcpt user:", err.Error())
        return fmt.Errorf("Error")
    }

    if !slices.Contains(user.Subaddresses, user_key[1]) {
        log.Println("User doesn't have this subaddress active:", user_key[1])
        return fmt.Errorf("User exists, but the subaddress is not correct")
    }

    s.To = append(s.To, ExtendedUser{
        User: user,
        Subaddress: user_key[1],
    })

    return nil
}

var metadata_size = 2.44 * 1024

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
    message_id := parsed_header.Get("Message-ID")
    subject := parsed_header.Get("Subject")

    encrypted_email, encryption_key, err := encryption.EncryptEmail(raw_body)

    log.Println("DH pub server:", s.Backend.DHPublicKey)

    email := mongo_schemes.Email{
        Encryption: mongo_schemes.Encryption_ECDH_MLKEM,
        From: s.From,
        Headers: string(raw_headers),
        Body: encrypted_email,
        DHPublicKey: s.Backend.DHPublicKey,
        ReferenceCount: len(s.To),
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
    estimated_size := email_size + int(metadata_size)

    var metadata []interface{}
    var to_ids []primitive.ObjectID
    for i := range s.To {
        user := &s.To[i]
        to_ids = append(to_ids, user.Id)
        ev, err := encryption.GenerateEncryptedKey(encryption_key, s.Backend.DHPrivateKey, &user.User)
        if err != nil {
            log.Println("Something failed when encrypting the email", err.Error())
            return fmt.Errorf("There was an error encrypting the emails")
        }

        m := mongo_schemes.Metadata{
            Size: estimated_size,
            KeyUsed: ev.UsedKey,
            UserEmail: user.Email,
            EmailID: inserted_id,
            MessageId: message_id,
            Subject: subject,
            From: s.From,
            Ciphertext: ev.CipherText,
            EncryptedKey: ev.SecondStageKey,
            Private: false,
            Subaddress: user.Subaddress,
        }

        metadata = append(metadata, m)
    }

    _, err = s.Backend.MetadataCollection.InsertMany(context.TODO(), metadata)
    if err != nil {
        log.Println("Error inserting metadata:", err.Error())
        return fmt.Errorf("Server error")
    }

    filter := bson.D{{Key: "_id", Value: bson.M{"$in": to_ids}}}
    update := bson.D{{Key: "$inc", Value: bson.M{"usage.used_space": estimated_size}}}
    _, err = s.Backend.UserCollection.UpdateMany(context.TODO(), filter, update)

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
