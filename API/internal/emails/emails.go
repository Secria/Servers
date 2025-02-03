package emails

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"secria_api/internal/api_utils"
	"shared/encryption"
	"shared/mongo_schemes"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Tuple[T any,V any] struct {
    first T
    second V
}

func forEach[T any](function func(index int, value T), elements []T) {
    for i, v := range elements {
        function(i, v)
    }
}

func mapFunc[T any,R any](function func(index int, value T) R, elements []T) []R {
    list := make([]R, len(elements))
    for i, v := range elements {
        list[i] = function(i, v)
    }
    return list
}

func mapFuncWithError[T any,R any](function func(index int, value T) (R, error), elements []T) ([]R, error) {
    list := make([]R, len(elements))
    for i, v := range elements {
        r, err := function(i, v)
        if err != nil {
            return nil, err
        }
        list[i] = r
    }
    return list, nil
}

func filterFunc[T any](function func(index int, value T) bool, elements []T) []T {
    list := make([]T, 0)
    for i, v := range elements {
        if function(i, v) {
            list = append(list, v)
        }
    }
    return list
}

func indexOf[T any](function func(index int, value T) bool, elements []T) int {
    for i, v := range elements {
        if function(i, v) {
            return i
        }
    }
    return -1
}

func sliceContains[T comparable](value T, elements []T) bool {
    if indexOf(func(_ int, v T) bool {return v == value}, elements) == -1 {
        return false
    }
    return true
}

func pairBy[T any,V any](first []T, second []V, function func(T,V) bool) []Tuple[T,V] {
    result := make([]Tuple[T,V], len(first))
    for i, f := range first {
        for _, s := range second {
            if function(f, s) {
                result[i] = Tuple[T, V]{f, s}
            }
        }
    }
    return result
}

func groupBy[T any, R comparable](function func(index int, value T) R, elements []T) map[R][]T {
    result := make(map[R][]T)
    for i, v := range elements {
        k := function(i, v)
        if result[k] == nil {
            result[k] = make([]T, 0)
        }
        result[k] = append(result[k], v)
    }
    return result
}

func sliceDistinct[T comparable](elements []T) []T {
    result := make([]T, 0)
    for _, v := range elements {
        if !sliceContains(v, result) {
            result = append(result, v)
        }
    }
    return result
}

func groupByWithError[T any, R comparable](function func(index int, value T) (R, error), elements []T) (map[R][]T, error) {
    result := make(map[R][]T)
    for i, v := range elements {
        k, e := function(i, v)
        if e != nil {
            return nil, e
        }
        if result[k] == nil {
            result[k] = make([]T, 0)
        }
        result[k] = append(result[k], v)
    }
    return result, nil
}

func QueryEmails(metadata_collection *mongo.Collection,email_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[[]api_utils.ResponseEmail](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        query := r.URL.Query()
        count_str := query.Get("count")
        skip_str := query.Get("skip")
        sent_str, sent := query["sent"]
        starred_str, starred := query["starred"]
        public_str, public := query["public"]
        used_address_str, used_address := query["address"]
        tags_str, tags := query["tag"]
        search_str, search := query["search"]
        _, deleted := query["deleted"]
        _, draft := query["draft"]
        _, archived := query["archived"]
        message_id, search_by_id := query["message_id"]

        var count, skip int
        if _, err := fmt.Sscan(count_str, &count); err != nil {
            count = 10
        }
        if _, err := fmt.Sscan(skip_str, &skip); err != nil {
            skip = 0
        }

        var filter bson.D
        if used_address {
            if !slices.Contains(user.Addresses, used_address_str[0]) && used_address_str[0] != user.MainEmail {
                responder.WriteError("Invalid address")
                return
            }
            filter = bson.D{{ Key: "used_address", Value: used_address_str[0]}}
        } else {
            filter = bson.D{{ Key: "used_address", Value: user.MainEmail}}
        }

        if (search_by_id) {
            decoded, err := base64.StdEncoding.DecodeString(message_id[0])
            if err != nil {
                log.Println("Failed to decode base64 message id:", err.Error())
                responder.WriteError("Malformed request")
                return
            }
            filter = append(filter, bson.E{Key: "message_id", Value: string(decoded)})
        } else {
            if archived {
                filter = append(filter, bson.E{Key: "archived", Value: true})
            } else {
                filter = append(filter, bson.E{Key: "archived", Value: bson.M{"$exists": false}})
            }

            if draft {
                filter = append(filter, bson.E{Key: "draft", Value: true})
            } else {
                filter = append(filter, bson.E{Key: "draft", Value: bson.M{"$exists": false}})
            }
            
            if deleted {
                filter = append(filter, bson.E{Key: "deleted", Value: true})
            } else {
                filter = append(filter, bson.E{Key: "deleted", Value: bson.M{"$exists": false}})
            }

            if sent {
                if sent_str[0] == "true" {
                    filter = append(filter, bson.E{Key: "sent", Value: true})
                } else {
                    filter = append(filter, bson.E{Key: "sent", Value: bson.M{"$exists": false}})
                }
            }

            if starred {
                if starred_str[0] == "true" {
                    filter = append(filter, bson.E{Key: "starred", Value: true})
                } else {
                    filter = append(filter, bson.E{Key: "starred", Value: bson.M{"$exists": false}})
                }
            }

            if public {
                if public_str[0] == "true" {
                    filter = append(filter, bson.E{Key: "private", Value: false})
                } else {
                    filter = append(filter, bson.E{Key: "private", Value: true})
                }
            }

            if tags {
                filter = append(filter, bson.E{Key: "tags", Value: tags_str[0]})
            }

            if search {
                decoded_search, err := base64.StdEncoding.DecodeString(search_str[0])
                if err != nil {
                    log.Println("Bad search string data: "+err.Error())
                    responder.WriteError("Malformed request")
                    return
                }
                filter = append(filter, bson.E{Key: "$text", Value: bson.M{
                    "$search": string(decoded_search),
                }})
            }
        }

        findOptions := options.Find()
        findOptions.SetSort(bson.D{{ Key: "_id", Value: 1 }})
        findOptions.SetLimit(int64(count))
        findOptions.SetSkip(int64(skip))

        cur, err := metadata_collection.Find(context.TODO(), filter, findOptions)
        if err != nil {
            log.Println("Error retrieving user emails:", err.Error())
            responder.WriteError("Error retrieving emails")
            return
        }
        defer cur.Close(context.TODO())

        found_count, err := metadata_collection.CountDocuments(context.TODO(), filter)
        if err != nil {
            log.Println("Error decoding emails", err.Error())
            responder.WriteError("Error retrieving emails")
            return
        }

        var metadata []mongo_schemes.Metadata = make([]mongo_schemes.Metadata, 0)
        if err := cur.All(context.TODO(), &metadata); err != nil {
            log.Println("Error decoding emails:", err.Error())
            responder.WriteError("Error retrieving emails")
            return
        }

        email_id := mapFunc(func(i int, v mongo_schemes.Metadata) primitive.ObjectID {
            return v.EmailID
        }, metadata)

        email_filter := bson.D{{Key: "_id", Value: bson.M{"$in": email_id}}}
        n_cur, err := email_collection.Find(context.Background(), email_filter)
        if err != nil {
            log.Println("Error retrieving user emails: "+err.Error())
            responder.WriteError("Error retrieving emails")
            return
        }
        defer n_cur.Close(context.Background())

        var queried_emails[]mongo_schemes.Email = make([]mongo_schemes.Email, 0)
        if err := n_cur.All(context.Background(), &queried_emails); err != nil {
            log.Println("Error retrieving emails: "+err.Error())
            responder.WriteError("Error retrieving emails")
            return
        }

        pair_emails := pairBy(metadata, queried_emails, func(m mongo_schemes.Metadata, e mongo_schemes.Email) bool {
            return m.EmailID == e.Id
        })

        response_emails := mapFunc(func(i int, v Tuple[mongo_schemes.Metadata, mongo_schemes.Email]) api_utils.ResponseEmail {
            metadata := v.first
            email := v.second
            return api_utils.ResponseEmail{
                Id: metadata.Id,
                Encryption: email.Encryption,
                KeyUsed: metadata.KeyUsed,
                From: email.From,
                MessageId: metadata.MessageId,
                Headers: email.Headers,
                Body: email.Body,
                CipherText: metadata.Ciphertext,
                EncryptedKey: metadata.EncryptedKey,
                DHPublicKey: email.DHPublicKey,
                Private: metadata.Private,
                Sent: metadata.Sent,
                Read: metadata.Read,
                Starred: metadata.Starred,
                Tags: metadata.Tags,
            }
        }, pair_emails)
        
        responder.WriteCountData(response_emails, int(found_count))
    })
}

type EncryptRecipient struct {
    Email string `json:"email"`
    Name string `json:"name"`
    KeyUsed string `json:"key_used"`
    Ciphertext string `json:"ciphertext"`
    EncryptedKey string `json:"encrypted_key"`
    Sender bool `json:"sender"`
    To bool `json:"to"`
    CC bool `json:"cc"`
    BCC bool `json:"bcc"`
}

type SendPrivateRequest struct {
    Encryption int `json:"encryption"`
    To []EncryptRecipient `json:"to"`
    Subject string `json:"subject"`
    Body string `json:"body"`
    ContentType string `json:"content_type"`
    Boundary string `json:"boundary"`
    InReplyTo string `json:"in_reply_to"`
    References string `json:"references"`
}

func check_array_match[T comparable](array []T, value T) bool {
    for _, e := range array {
        if value == e {
            return true
        }
    }
    return false
}

func list_email_header_format(recipients []EncryptRecipient) string {
    result := ""
    for i, r := range recipients {
        if i == len(recipients)-1 && r.Name != "" {
            result += fmt.Sprintf(" \"%s\" <%s>", r.Name, r.Email)
        } else if i == len(recipients)-1 {
            result += fmt.Sprintf(" <%s>", r.Email)
        } else if r.Name != "" {
            result += fmt.Sprintf(" \"%s\" <%s>,", r.Name, r.Email)
        } else {
            result += fmt.Sprintf(" <%s>,", r.Email)
        }
    }
    return result
}

var boundary_regex = regexp.MustCompile("[0-9a-f]{24}")

func check_valid_boundary(boundary string) bool {
    return boundary_regex.Match([]byte(boundary))
}

func SendPrivate(users_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection, metadata_size *int) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        if user.Usage.SentEmails >= user.PlanConfig.DailyEmailLimit {
            responder.WriteError("Exceeded daily emails sent")
            return
        }

        var send_request SendPrivateRequest 
        if err := json.NewDecoder(r.Body).Decode(&send_request); err != nil {
            log.Println("Error decoding request:", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        to_emails := filterFunc(func(i int, e EncryptRecipient) bool { return e.To}, send_request.To)
        if len(to_emails) == 0 {
            log.Println("Tried to send an email without to recipients")
            responder.WriteError("No recipients specified")
            return
        }

        cc_emails := filterFunc(func(i int, e EncryptRecipient) bool { return e.CC}, send_request.To)
        
        email_id := primitive.NewObjectID()
        message_id := fmt.Sprintf("<%s@secria.me>", email_id.Hex()) // Change when more domains are allowed

        headers := fmt.Sprintf("From: \"%s\" <%s>\r\n", user.Name, user.MainEmail)
        headers += fmt.Sprintf("To:%s\r\n", list_email_header_format(to_emails))
        if len(cc_emails) != 0 {
            headers += fmt.Sprintf("CC:%s\r\n", list_email_header_format(cc_emails)) // First space is included in the function
        }
        if len(send_request.Subject) != 0 {
            headers += fmt.Sprintf("Subject: %s\r\n", send_request.Subject)
        }
        headers += fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z))
        headers += fmt.Sprintf("Message-Id: %s\r\n", message_id)

        if send_request.InReplyTo != "" {
            headers += fmt.Sprintf("In-Reply-To: %s", send_request.InReplyTo)
            if send_request.References != "" {
                headers += fmt.Sprintf("References: %s %s", send_request.InReplyTo, send_request.References)
            }
        }

        if !check_valid_boundary(send_request.Boundary) {
            responder.WriteError("Bad boundary format")
            return
        }

        if send_request.ContentType == "multipart/mixed" || send_request.ContentType == "multipart/alternative" {
            headers += fmt.Sprintf("Content-Type: %s; boundary=%s", send_request.ContentType, send_request.Boundary)
        }

        email := mongo_schemes.Email{
            Id: email_id,
            From: user.MainEmail,
            Encryption: mongo_schemes.Encryption_ECDH_MLKEM,
            Body: send_request.Body,
            Headers: headers,
        }

        email_bson, err := bson.Marshal(email)
        if err != nil {
            log.Println("There was an error creating the email:", err.Error())
            responder.WriteError("Server error")
            return
        }

        estimated_size := len(email_bson) + *metadata_size

        raw_email := bson.Raw(email_bson)

        _, err = email_collection.InsertOne(context.Background(), raw_email)

        if err != nil {
            log.Println("There was an error creating the email:",err.Error())
            responder.WriteError("Server error")
            return
        }

        list := mapFunc(func(i int, u EncryptRecipient) interface{} {
            m := mongo_schemes.Metadata{
                UsedAddress: u.Email,
                Size: estimated_size,
                KeyUsed: u.KeyUsed,
                EmailID: email_id,
                Subject: send_request.Subject,
                MessageId: message_id,
                From: user.MainEmail,
                Private: true,
                EncryptedKey: u.EncryptedKey,
                Ciphertext: u.Ciphertext,
            }
            if u.Sender {
                m.Sent = true
            } else if u.BCC {
                m.BCC = true
            }
            return m
        },
        send_request.To)

        _, err = metadata_collection.InsertMany(context.Background(), list)
        if err != nil {
            log.Println("There was an error creating the email metadata:", err.Error())
            responder.WriteError("Server error")
            return
        }

        user_emails := mapFunc(func(i int, u EncryptRecipient) string { return u.Email }, send_request.To)

        filter := bson.D{{Key: "email", Value: bson.M{"$in": user_emails}}}
        update := bson.D{
            {Key: "$inc", Value: bson.M{"usage.used_space": estimated_size}},
        }

        // Update other users
        _, err = users_collection.UpdateMany(context.TODO(), filter, update)

        if err != nil {
            log.Println("Error updating used size:", err.Error())
            responder.WriteError("Server error")
            return
        }

        // Update sending user
        sent_emails_today := user.Usage.SentEmails + 1
        if time.Now().After(user.Usage.ResetDate) {
            sent_emails_today = 1
            update = append(update, bson.E{Key: "$set", Value: bson.M{"usage.sent_emails": sent_emails_today}})
            now := time.Now().UTC()
            update = append(update, bson.E{Key: "$set", Value: bson.M{"usage.reset_date": time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())}})
        }

        _, err = users_collection.UpdateByID(context.TODO(), user.Id, update)

        if err != nil {
            log.Println("Error updating used size:", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Email sent correctly")
    })
}

func split_user_domain(email string) (string, string, error) {
    d := strings.Split(email, "@")
    if len(d) != 2 {
        return "", "", errors.New("email contains more than one @: "+email)
    }
    return d[0], d[1], nil
}

func check_domain_ownership(email string) bool {
    return email == "secria.com"
}

func split_user_sub(user string) (string, string, error) {
    user_parts := strings.Split(user, "+")
    if len(user_parts) != 2 {
        return "", "", errors.New("malformed subaddress"+user)
    }
    username := user_parts[0]
    subaddress := user_parts[1]
    return username, subaddress, nil
}

// func store_owned_messages(ctx context.Context, user_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection, from string, recipients []RecipientDomainWrapper, headers map[string]string, body string) chan error {
func store_owned_messages(ctx context.Context, user_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection, from string, recipients []RecipientDomainWrapper, body string) chan error {
    ch := make(chan error)
    go func() {
        owned_emails := mapFunc(func(i int, r RecipientDomainWrapper) string { return r.Email }, recipients)
        filter := bson.D{{Key: "email", Value: bson.M{"$in": owned_emails}}}

        cur, err := user_collection.Find(context.Background(), filter)
        if err != nil {
            ch <- err
            return
        }
        defer cur.Close(context.Background())

        var users []mongo_schemes.User = make([]mongo_schemes.User, 0)
        if err := cur.All(context.Background(), &users); err != nil {
            ch <- err
            return
        }

        email_key := make([]byte, 32)
        _, err = rand.Read(email_key)
        if err != nil {
            ch <- err
            return
        }

        encrypted_body_encoded, err := encryption.AesEncryptCBC(email_key, []byte(body))
        if err != nil {
            ch <- err
            return
        }

        dh_throw_priv, err := ecdh.P256().GenerateKey(rand.Reader)
        if err != nil {
            ch <- err
            return
        }

        dh_throw_pub := dh_throw_priv.PublicKey()
        dh_throw_pub_encoded := base64.StdEncoding.EncodeToString(dh_throw_pub.Bytes())

        metadata := make([]mongo_schemes.Metadata, 0, len(recipients))
        for _, recipient := range recipients {
            found := false
            for _, user := range users {
                if user.MainEmail == recipient.Email {
                    recipient_key := user.MainKey

                    mlkem_pub_bytes := make([]byte, 0)
                    _, err := base64.StdEncoding.Decode(mlkem_pub_bytes, []byte(recipient_key.MLKEMPublicKey))
                    if err != nil {
                        ch <- err
                        return
                    }

                    dh_pub := make([]byte, 0)
                    _, err = base64.StdEncoding.Decode(dh_pub, []byte(recipient_key.DHPublicKey))
                    if err != nil {
                        ch <- err
                        return
                    }
                    dh_pub_key, err := ecdh.P256().NewPublicKey(dh_pub)
                    if err != nil {
                        ch <- err
                        return
                    }

                    dh_shared_secret, err := dh_throw_priv.ECDH(dh_pub_key)
                    if err != nil {
                        ch <- err
                        return
                    }

                    mlkem_pub, err := mlkem.NewEncapsulationKey1024(mlkem_pub_bytes)

                    ciphertext, mlkem_shared_secret := mlkem_pub.Encapsulate()
                    if err != nil {
                        ch <- err
                        return
                    }

                    var shared_secret [32]byte
                    for i := range mlkem_shared_secret {
                        shared_secret[i] = dh_shared_secret[i] ^ mlkem_shared_secret[i]
                    }

                    shared_secret = sha256.Sum256(shared_secret[:])

                    encrypted_email_key_encoded, err := encryption.AesEncryptGCM(shared_secret[:], email_key)

                    ciphertext_encoded := base64.StdEncoding.EncodeToString(ciphertext)


                    m := mongo_schemes.Metadata{
                        UsedAddress: recipient.Email,
                        KeyUsed: recipient_key.KeyId,
                        Ciphertext: ciphertext_encoded,
                        EncryptedKey: encrypted_email_key_encoded,
                    }
                    if recipient.Sender {
                        m.Sent = true
                    }
                    if recipient.BCC {
                        m.BCC = true
                    }

                    metadata = append(metadata, m)
                    found = true
                    break
                }
            }

            if found != true {
                ch <- fmt.Errorf("failed to find user: %s",recipient.Email)
                return
            }
        }

        email := mongo_schemes.Email{
            From: from,
            // Headers: headers,
            Body: encrypted_body_encoded,
            DHPublicKey: dh_throw_pub_encoded,
        }

        email_res, err := email_collection.InsertOne(ctx, email)
        if err != nil {
            ch <- err
            return
        }

        email_id := email_res.InsertedID.(primitive.ObjectID)

        final_metadata := mapFunc(func(i int, m mongo_schemes.Metadata) interface{} {
            m.EmailID = email_id
            return m
        }, 
        metadata)

        _, err = metadata_collection.InsertMany(ctx, final_metadata)

        // Handle errors outside
        ch <- err
    }()
    return ch
}

func send_emails_to_domain(from string, users []RecipientDomainWrapper, domain string, message []byte) chan error {
    ret := make(chan error)

    go func() {
        domain_emails := mapFunc(func(i int, u RecipientDomainWrapper) string { return u.Email }, users)
        url := domain + ":smtp"
        client, err := smtp.Dial(url)
        if err != nil {
            ret <- err
            return
        }

        err = client.SendMail(from, domain_emails, bytes.NewReader(message))

        // Handle errors in main
        ret <- err
    }()
    return ret
}

type Destination int

type Recipient struct {
    Email string `json:"email"`
    Sender bool `json:"sender"`
    To bool `json:"to"`
    CC bool `json:"cc"`
    BCC bool `json:"bcc"`
}

type RecipientDomainWrapper struct {
    Recipient
    Username string
    Subaddress string
    Domain string
}

type SendPublicRequest struct {
    To []string `json:"to"`
    CC []string `json:"cc"`
    BCC []string `json:"bcc"`
    Address string `json:"address"`
    Subject string `json:"subject"`
    Body string `json:"body"`
}

func SendPublic(users_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        var send_request SendPublicRequest
        if err := json.NewDecoder(r.Body).Decode(&send_request); err != nil {
            log.Println("Error decoding request: "+err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        valid_addresses := append(user.Addresses, user.MainEmail)

        if !slices.Contains(valid_addresses, send_request.Address) {
            log.Println("Subaddress was not found")
            responder.WriteError("Subaddress was not found")
            return
        }

        to_length := len(send_request.To)
        cc_length := len(send_request.CC)
        bcc_length := len(send_request.BCC)
        length := to_length + cc_length + bcc_length + 1

        var users []RecipientDomainWrapper = make([]RecipientDomainWrapper, 0, length)
        for i, address := range send_request.To {
            username, domain, err := split_user_domain(address)
            if err != nil {
                log.Println("Malformed address: "+address)
                responder.WriteError("Malformed address:", address)
                return
            }
            recipient := RecipientDomainWrapper{
                Recipient: Recipient{
                    Email: address,
                },
                Username: username,
                Domain: domain,
            }
            if i < to_length {
                recipient.To = true
            } else if i < cc_length {
                recipient.CC = true
            } else if i < bcc_length {
                recipient.BCC = true
            } else {
                recipient.Sender = true
            }
            users = append(users, recipient)
        }

        users_by_domain := groupBy(func(i int, v RecipientDomainWrapper) string  { return v.Domain}, users)

        var owned_domain_users []RecipientDomainWrapper = make([]RecipientDomainWrapper, 0)
        var outbound_domains []string = make([]string, 0)
        for d, v := range users_by_domain {
            if check_domain_ownership(d) {
                for _, u := range v {
                    username, subaddress, err := split_user_sub(u.Username)
                    if err != nil {
                        log.Println("There was an error parsing the username: "+err.Error())
                        responder.WriteError("Malformed secria user recipient")
                        return
                    }
                    u.Username = username
                    u.Subaddress = subaddress
                    owned_domain_users = append(owned_domain_users, u)
                }
            } else {
                outbound_domains = append(outbound_domains, d)
            }
        }

        // from := user.Username + "+" + send_request.Address + "@" + user.Domain;
        from := user.MainEmail // This is wrong

        headers := "From: " + send_request.Address + "\r\n"
        headers += "To" + strings.Join(send_request.To, ", ") + "\r\n"
        headers += "CC" + strings.Join(send_request.CC, ", ") + "\r\n"
        headers += "Subject" + send_request.Subject + "\r\n"
        headers += "\r\n"

        body := headers + send_request.Body

        owned_channel := store_owned_messages(context.Background(), users_collection, metadata_collection, email_collection, from, owned_domain_users, body)

        outbound_channels := make([]chan error, 0)
        for k, v := range users_by_domain {
            // ch := send_emails_to_domain(from, v, k, []byte(message))
            ch := send_emails_to_domain(from, v, k, []byte(body))
            outbound_channels = append(outbound_channels, ch)
        }

        err := <- owned_channel
        if err != nil {
            log.Println("There was an error creating the public email: "+err.Error())
            responder.WriteError("Server error")
            return
        }

        for _, ch := range outbound_channels {
            err := <- ch
            if err != nil {
                log.Println("There was an error sending the public email: "+err.Error())
                responder.WriteError("Failed to connect to domain")
                return
            }
        }
        
        responder.WriteData("Email sent correctly")
    })
}

type FlagEmailsRequest struct {
    EmailID []primitive.ObjectID `json:"email_id"`
    Value bool `json:"value"`
}

func MarkEmailsRead(metadata_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)

        var mark_read_request FlagEmailsRequest 
        if err := json.NewDecoder(r.Body).Decode(&mark_read_request); err != nil {
            log.Println("Failed to parse mark read request:", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        filter := bson.M{"_id": bson.M{"$in": mark_read_request.EmailID}}

        var update bson.D
        if mark_read_request.Value == true {
            update = bson.D{{Key: "$set", Value: bson.M{"read": true}}}
        } else {
            update = bson.D{{Key: "$unset", Value: bson.M{"read": false}}}
        }

        _, err := metadata_collection.UpdateMany(context.Background(), filter, update)
        if err != nil {
            log.Println("Failed to update email:", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Updated email")
    })
}

func StarEmails(metadata_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        //user := r.Context().Value("user").(mongo_schemes.User)

        var star_request FlagEmailsRequest 
        if err := json.NewDecoder(r.Body).Decode(&star_request); err != nil {
            log.Println("Failed to parse mark read request")
            responder.WriteError("Invalid request body")
            return
        }

        filter := bson.M{"_id": bson.M{"$in": star_request.EmailID}}

        var update bson.D
        if star_request.Value == true {
            update = bson.D{{Key: "$set", Value: bson.M{"starred": true}}}
        } else {
            update = bson.D{{Key: "$unset", Value: bson.M{"starred": ""}}}
        }

        _, err := metadata_collection.UpdateMany(context.Background(), filter, update)
        if err != nil {
            log.Println("Failed to update email: "+err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Starred email")
    })
}

func ArchiveEmails(metadata_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        //user := r.Context().Value("user").(mongo_schemes.User)

        var archive_request FlagEmailsRequest 
        if err := json.NewDecoder(r.Body).Decode(&archive_request); err != nil {
            log.Println("Failed to parse mark read request")
            responder.WriteError("Invalid request body")
            return
        }

        filter := bson.M{"_id": bson.M{"$in": archive_request.EmailID}}

        var update bson.D
        if archive_request.Value == true {
            update = bson.D{{Key: "$set", Value: bson.M{"archived": true}}}
        } else {
            update = bson.D{{Key: "$unset", Value: bson.M{"archived": ""}}}
        }

        _, err := metadata_collection.UpdateMany(context.Background(), filter, update)
        if err != nil {
            log.Println("Failed to update email: "+err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Archived email")
    })
}

type TagEmailsRequest struct {
    EmailID []primitive.ObjectID `json:"email_id"`
    Tags []string `json:"tags"`
}

func TagEmails(metadata_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        var tag_request TagEmailsRequest 
        if err := json.NewDecoder(r.Body).Decode(&tag_request); err != nil {
            log.Println("Failed to parse tag emails request")
            responder.WriteError("Invalid request body")
            return
        }

        user_tags := mapFunc(func(i int, u mongo_schemes.UserTag) string { return u.Name}, user.Tags)
        for _, tag := range tag_request.Tags {
            if !sliceContains(tag, user_tags) {
                log.Println("User tried to set a non existing tag: "+tag)
                responder.WriteError("Invalid tag")
                return
            }
        }

        filter := bson.M{"_id": bson.M{"$in": tag_request.EmailID}}

        var update bson.M
        if len(tag_request.Tags) == 0 {
            update = bson.M{
                "$unset": bson.M{
                    "tags": true,
                },
            }
        } else {
            update = bson.M{
                "$set": bson.M{
                    "tags": tag_request.Tags,
                },
            }
        }

        _, err := metadata_collection.UpdateMany(context.Background(), filter, update)
        if err != nil {
            log.Println("Failed to update email: "+err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Added tags to email")
    })
}

func CleanupEmails(email_collection *mongo.Collection, cleanup_rate int64) func(int64) {
    var deleted atomic.Int64
    return func(i int64) {
        s := deleted.Add(i)
        if deleted.CompareAndSwap(cleanup_rate, 0) {
            del := bson.M{"reference_count": 0}
            res, err := email_collection.DeleteMany(context.Background(), del)
            if err != nil {
                deleted.Add(s)
                return
            }
            log.Printf("Cleanup emails deleted %d emails", res.DeletedCount)
        }
    }
}

type DeleteEmailRequest struct {
    EmailID []primitive.ObjectID `json:"email_id"`
}

func DeleteEmails(metadata_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        var delete_email_request DeleteEmailRequest 
        if err := json.NewDecoder(r.Body).Decode(&delete_email_request); err != nil {
            log.Println("Failed to parse mark read request: "+err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        filter := bson.D{
            {Key: "user_email", Value: user.MainEmail},
            {Key: "_id", Value: bson.M{
                "$in": delete_email_request.EmailID,
            }},
        }
        update := bson.D{{Key: "$set", Value: bson.M{
            "deleted": true,
        }}}

        _, err := metadata_collection.UpdateMany(context.TODO(), filter, update)
        if err != nil {
            log.Println("Failed to set deleted tag: "+err.Error())
            responder.WriteError("Failed to delete")
            return
        }

        responder.WriteData("Deleted emails")
    })
}
