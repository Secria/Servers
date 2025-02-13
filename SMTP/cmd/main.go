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

	"shared/mongo_schemes"
    "shared/encryption"
    "shared/usage"

	"github.com/emersion/go-message"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

var ENV string
var MONGO_URI string
var S3_ENDPOINT string
var ACCESS_KEY_ID string
var SECRET_ACCESS_KEY string
var BUCKET_NAME string
var REGION string

func main() {
    ENV = os.Getenv("ENVIRONMENT")
    MONGO_URI = os.Getenv("MONGO_URI");
    S3_ENDPOINT = os.Getenv("S3_ENDPOINT")
    ACCESS_KEY_ID = os.Getenv("ACCESS_KEY_ID")
    SECRET_ACCESS_KEY = os.Getenv("SECRET_ACCESS_KEY")
    BUCKET_NAME = os.Getenv("BUCKET_NAME")
    REGION = os.Getenv("REGION")

    minio_client, err := minio.New(S3_ENDPOINT, &minio.Options{
        Creds: credentials.NewStaticV4(ACCESS_KEY_ID, SECRET_ACCESS_KEY, ""),
        Secure: false,
    })
    if err != nil {
        log.Fatalln(err)
    }

    CreateBucket(minio_client)

    if err != nil {
        log.Fatalf("Failed to load AWS config: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second);
    defer cancel();
    mongo_client, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGO_URI))
    if err != nil {
        log.Panicln("Failed to connect to mongo db")
    }
    db := mongo_client.Database("Secria");
    user_collection := db.Collection("Users");
    email_collection := db.Collection("Emails");
    metadata_collection := db.Collection("EmailMetadata");
    usage_collection := db.Collection("Usage")

    dh_priv, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal("Failed to generate dh private key")
    }

    dh_pub := dh_priv.PublicKey().Bytes()

    backend := &Backend{
        S3Client: minio_client,
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
    S3Client *minio.Client
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

func StoreAttachment(filename string, r io.Reader) error {
    content, err := io.ReadAll(r)
    if err != nil {
        return err
    }
    log.Println("Name", filename)
    log.Println("Content", string(content))
    return nil
}

type Attachment struct {
    Filename string
    ContentType string
    Reader io.Reader
}

func ParseMessageAndStore(m *message.Entity) (*bytes.Buffer, []Attachment, error) {
	var b bytes.Buffer
	w, err := message.CreateWriter(&b, m.Header)
	if err != nil {
		log.Fatal(err)
	}

    var attachments []Attachment = make([]Attachment, 0)
	var transform func(w *message.Writer, e *message.Entity) error
	transform = func(w *message.Writer, e *message.Entity) error {
		if mr := e.MultipartReader(); mr != nil {
			// This is a multipart entity, transform each of its parts
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				} else if err != nil {
					return err
				}

                contentType, _, _ := p.Header.ContentType()
                disposition, params, _ := p.Header.ContentDisposition()
                if disposition == "attachment" {
                    filename, ok := params["filename"]
                    if !ok {
                        filename = "No name"
                    }
                    attachments = append(attachments, Attachment{Filename: filename, ContentType: contentType, Reader: p.Body})
                    return nil
                }

				pw, err := w.CreatePart(p.Header)
				if err != nil {
					return err
				}

				if err := transform(pw, p); err != nil {
					return err
				}

				pw.Close()
			}
			return nil
		} else {
			body := e.Body
			_, err := io.Copy(w, body)
			return err
		}
	}

	if err := transform(w, m); err != nil {
        return nil, nil, err
	}
	w.Close()

	return &b, attachments, nil
}

func (s *Session) Data(r io.Reader) error { 
	m, err := message.Read(r)
	if message.IsUnknownCharset(err) {
		log.Println("Unknown encoding:", err)
	} else if err != nil {
		log.Fatal(err)
	}
    buf, attachments, err := ParseMessageAndStore(m)
    if err != nil {
        log.Println("Error storing attachments", err)
        return fmt.Errorf("Server error")
    }

    raw_headers, raw_body, err := splitCRLF(buf)

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
    if err != nil {
        log.Println("Failed encrypting email", err)
        return fmt.Errorf("Server error")
    }

    var attachment_size int64 = 0
    var DbAttachments []mongo_schemes.Attachment
    for _, a := range attachments {
        buf, err := io.ReadAll(a.Reader)
        if err != nil {
            log.Println("Failed to read", err)
            return err
        }
        encrypted, err := encryption.AesEncryptCBC(encryption_key, buf)
        log.Println("Attachment", encrypted)
        if err != nil {
            log.Println("Error encrypting attachment", err)
            return err
        }
        reader := bytes.NewReader(encrypted)
        uuid := uuid.New().String()
        size := int64(len(encrypted))
        attachment_size += size
        if attachment_size >= 25 * 1024 * 1024 {
            log.Println("Attachment size too big")
            return fmt.Errorf("Attachments overpass 25MB")
        }
        _, err = s.Backend.S3Client.PutObject(context.TODO(), BUCKET_NAME, uuid, reader, size, minio.PutObjectOptions{})
        if err != nil {
            log.Println("Error uploading attachment", err)
            return err
        }
        DbAttachments = append(DbAttachments, mongo_schemes.Attachment{
            Filename: a.Filename,
            ContentType: a.ContentType,
            Size: size,
            Reference: uuid,
        })
    }


    email := mongo_schemes.Email{
        Encryption: mongo_schemes.Encryption_ECDH_MLKEM,
        From: s.From,
        Headers: string(raw_headers),
        Body: encrypted_email,
        DHPublicKey: s.Backend.DHPublicKey,
        Attachments: DbAttachments,
    }

    encoded_email, err := bson.Marshal(email)
    email_size := len(encoded_email)
    if email_size >= 10 * 1024 * 1024 {
        log.Println("Email size is too big")
        return fmt.Errorf("Email size too big, 10MB max")
    }
    email_bson := bson.Raw(encoded_email)

    res, err := s.Backend.EmailCollection.InsertOne(context.TODO(), email_bson)
    if err != nil {
        log.Println("Error inserting email:", err.Error())
        return fmt.Errorf("Server error")
    }

    inserted_id := res.InsertedID.(primitive.ObjectID)
    estimated_size := int64(email_size) + attachment_size + metadata_size

    if message_id == "" {
        message_id = fmt.Sprintf("<%s@%s>", inserted_id.Hex(), s.FromDomain)
    }


    var metadata []interface{}
    var to_emails []string
    for i := range s.To {
        user := &s.To[i]

        usage, err := usage.GetUsage(context.TODO(), s.Backend.UsageCollection, user.MainEmail)
        if err != nil {
        }

        if usage.UsedSpace < user.PlanConfig.SpaceLimit {
            to_emails = append(to_emails, user.MainEmail)
            ev, err := encryption.GenerateEncryptedKey(encryption_key, s.Backend.DHPrivateKey, &user.User)
            if err != nil {
                log.Println("Something failed when encrypting the email", err.Error())
                return fmt.Errorf("There was an error encrypting the emails")
            }

            has_attachment := false
            if len(DbAttachments) != 0 {
                has_attachment = true
            }

            m := mongo_schemes.Metadata{
                Size: estimated_size,
                Ciphertext: ev.CipherText,
                EncryptedKey: ev.SecondStageKey,
                Salt: ev.Salt,
                KeyUsed: ev.UsedKey,
                UsedAddress: user.Address,
                EmailID: inserted_id,
                MessageId: message_id,
                Subject: subject,
                From: s.From,
                Private: false,
                Attachment: has_attachment,
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
