package emails

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"secria_api/internal/api_utils"
	"shared/mongo_schemes"
	"shared/usage"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type EmailDBResponse struct {
    Metadata mongo_schemes.Metadata `bson:"metadata"`
    Email mongo_schemes.Email `bson:"email"`
}

type QueryDBResponse struct {
    Data []EmailDBResponse `bson:"data"`
    Count int `bson:"count"`
}

func getEmailByFilter(ctx context.Context, metadata_collection *mongo.Collection, filter interface{}) (EmailDBResponse, error) {
        match_stage := bson.D{{Key: "$match", Value: filter}}
        limit_stage := bson.D{{Key: "$limit", Value: 1}}
        replace_stage := bson.D{{Key: "$replaceRoot", Value: bson.M{
            "newRoot": bson.M{
                "metadata": "$$ROOT",
            },
        }}}
        lookup_stage := bson.D{{Key: "$lookup", Value: bson.M{
            "from": "Emails",
            "localField": "metadata.email_id",
            "foreignField": "_id",
            "as": "email",
        }}}
        cleanup_stage := bson.D{{Key: "$set", Value: bson.M{"email": bson.M{"$arrayElemAt": bson.A{"$email", 0}}}}}
        cur, err := metadata_collection.Aggregate(ctx, mongo.Pipeline{match_stage, limit_stage, replace_stage, lookup_stage, cleanup_stage})

        if err != nil {
            return EmailDBResponse{}, err
        }
        defer cur.Close(ctx)

        var emails_response EmailDBResponse

        if cur.Next(ctx) {
            if err := cur.Decode(&emails_response); err != nil {
                return EmailDBResponse{}, err
            }
        } else {
            return EmailDBResponse{}, err
        }
        return emails_response, nil
}

func getEmailsAndCountByFilter(ctx context.Context, metadata_collection *mongo.Collection, filter interface{}, skip int, count int) (QueryDBResponse, error) {
        match_stage := bson.D{{Key: "$match", Value: filter}}
        sort_stage := bson.D{{Key: "$sort", Value: bson.D{{Key: "_id", Value: -1}}}}
        replace_stage := bson.D{{Key: "$replaceRoot", Value: bson.M{
            "newRoot": bson.M{
                "metadata": "$$ROOT",
            },
        }}}
        lookup_stage := bson.D{{Key: "$lookup", Value: bson.M{
            "from": "Emails",
            "localField": "metadata.email_id",
            "foreignField": "_id",
            "as": "email",
        }}}
        cleanup_stage := bson.D{{Key: "$set", Value: bson.M{"email": bson.M{"$arrayElemAt": bson.A{"$email", 0}}}}}
        separate_calc_stage := bson.D{{Key: "$facet", Value: bson.M{
            "data": bson.A{
                bson.D{{Key: "$skip", Value: skip}},
                bson.D{{Key: "$limit", Value: count}},
            },
            "count": bson.A{
                bson.D{{Key: "$count", Value: "count"}},
            },
        }}}
        replace_count_stage := bson.D{{Key: "$set", Value: bson.M{
            "count": bson.M{
                "$arrayElemAt": bson.A{"$count.count", 0},
            },
        }}}
        cur, err := metadata_collection.Aggregate(ctx, mongo.Pipeline{match_stage, sort_stage, replace_stage, lookup_stage, cleanup_stage, separate_calc_stage, replace_count_stage})

        if err != nil {
            return QueryDBResponse{}, err
        }
        defer cur.Close(context.TODO())

        var emails_response QueryDBResponse

        if cur.Next(context.TODO()) {
            if err := cur.Decode(&emails_response); err != nil {
                return QueryDBResponse{}, err
            }
        } else {
            return QueryDBResponse{}, err
        }
        return emails_response, nil
}

func QueryEmails(metadata_collection *mongo.Collection, email_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[[]api_utils.ResponseEmail](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        query := r.URL.Query()
        count_str := query.Get("count")
        skip_str := query.Get("skip")
        sent_str, sent := query["sent"]
        starred_str, starred := query["starred"]
        read_str, read := query["read"]
        public_str, public := query["public"]
        used_address_str, used_address := query["address"]
        tags_str, tags := query["tag"]
        search_str, search := query["search"]
        _, deleted := query["deleted"]
        _, draft := query["draft"]
        _, archived := query["archived"]
        _, attachment := query["attachment"]
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

            if read {
                if read_str[0] == "true" {
                    filter = append(filter, bson.E{Key: "read", Value: true})
                } else {
                    filter = append(filter, bson.E{Key: "read", Value: bson.M{"$exists": false}})
                }
            }

            if attachment {
                filter = append(filter, bson.E{Key: "attachment", Value: true})
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
                    log.Println("Bad search string data: ", err.Error())
                    responder.WriteError("Malformed request")
                    return
                }
                filter = append(filter, bson.E{Key: "$text", Value: bson.M{
                    "$search": string(decoded_search),
                }})
            }
        }

        match_stage := bson.D{{Key: "$match", Value: filter}}
        sort_stage := bson.D{{Key: "$sort", Value: bson.D{{Key: "_id", Value: -1}}}}
        replace_stage := bson.D{{Key: "$replaceRoot", Value: bson.M{
            "newRoot": bson.M{
                "metadata": "$$ROOT",
            },
        }}}
        lookup_stage := bson.D{{Key: "$lookup", Value: bson.M{
            "from": "Emails",
            "localField": "metadata.email_id",
            "foreignField": "_id",
            "as": "email",
        }}}
        cleanup_stage := bson.D{{Key: "$set", Value: bson.M{"email": bson.M{"$arrayElemAt": bson.A{"$email", 0}}}}}
        separate_calc_stage := bson.D{{Key: "$facet", Value: bson.M{
            "data": bson.A{
                bson.D{{Key: "$skip", Value: skip}},
                bson.D{{Key: "$limit", Value: count}},
            },
            "count": bson.A{
                bson.D{{Key: "$count", Value: "count"}},
            },
        }}}
        replace_count_stage := bson.D{{Key: "$set", Value: bson.M{
            "count": bson.M{
                "$arrayElemAt": bson.A{"$count.count", 0},
            },
        }}}
        cur, err := metadata_collection.Aggregate(context.TODO(), mongo.Pipeline{match_stage, sort_stage, replace_stage, lookup_stage, cleanup_stage, separate_calc_stage, replace_count_stage})

        if err != nil {
            log.Println("Error retrieving user emails:", err.Error())
            responder.WriteError("Error retrieving emails")
            return
        }
        defer cur.Close(context.TODO())

        var emails_response QueryDBResponse

        if cur.Next(context.TODO()) {
            if err := cur.Decode(&emails_response); err != nil {
                log.Println("Error decoding emails:", err.Error())
                responder.WriteError("Server errror")
                return
            }
        } else {
                log.Println("Error getting query db response")
                responder.WriteError("Server error")
                return
        }
        var emails []api_utils.ResponseEmail = make([]api_utils.ResponseEmail, 0)
        for _, v := range emails_response.Data {
            emails = append(emails, api_utils.ResponseEmail{
                Id: v.Metadata.Id,
                EmailId: v.Email.Id,
                Encryption: v.Email.Encryption,
                KeyUsed: v.Metadata.KeyUsed,
                EncryptedKey: v.Metadata.EncryptedKey,
                CipherText: v.Metadata.Ciphertext,
                DHPublicKey: v.Email.DHPublicKey,
                Salt: v.Metadata.Salt,
                From: v.Metadata.From,
                MessageId: v.Metadata.MessageId,
                Headers: v.Email.Headers,
                Body: v.Email.Body,
                Private: v.Metadata.Private,
                Sent: v.Metadata.Sent,
                Read: v.Metadata.Read,
                Starred: v.Metadata.Starred,
                Deleted: v.Metadata.Deleted,
                Draft: v.Metadata.Draft,
                Tags: v.Metadata.Tags,
                Attachments: v.Email.Attachments,
            })
        }

        responder.WriteCountData(emails, emails_response.Count)
    })
}

type EncryptRecipient struct {
    Email string `json:"email"`
    Name string `json:"name"`
    KeyUsed []byte `json:"key_used"`
    Ciphertext []byte `json:"ciphertext"`
    EncryptedKey []byte `json:"encrypted_key"`
    Salt []byte `json:"salt"`
    Sender bool `json:"sender"`
    To bool `json:"to"`
    CC bool `json:"cc"`
    BCC bool `json:"bcc"`
    Plaintext bool `json:"plaintext"`
}

type SendRequest struct {
    Encryption int `json:"encryption"`
    To []EncryptRecipient `json:"to"`
    Subject string `json:"subject"`
    Body []byte `json:"body"`
    PublicKey []byte `json:"public_key"`
    PlaintextBody string `json:"plaintext"`
    ContentType string `json:"content_type"`
    Boundary string `json:"boundary"`
    InReplyTo string `json:"in_reply_to"`
    References string `json:"references"`
    DraftId string `json:"draft_id"`
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

func send_outbound_emails() {
}

func SendEmail(users_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection, usage_collection *mongo.Collection, metadata_size *int64) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        tracked_usage, err := usage.GetUsage(context.TODO(), usage_collection, user.MainEmail)
        if err != nil {
            log.Println("Error retrieving usage:", err.Error())
            responder.WriteError("Server error")
            return
        }

        if tracked_usage.SentEmails >= user.PlanConfig.DailyEmailLimit {
            responder.WriteError("Exceeded daily emails sent")
            return
        }

        send_request, err := api_utils.DecodeJson[SendRequest](r.Body)
        if err != nil {
            log.Println("Error decoding request:", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        var to_emails []EncryptRecipient
        var cc_emails []EncryptRecipient
        var plaintext_emails []string
        var encrypted_emails []string
        for _, r := range send_request.To {
            if r.To {
                to_emails = append(to_emails, r)
            } else if r.CC {
                cc_emails = append(cc_emails, r)
            }
            if r.Plaintext {
                plaintext_emails = append(plaintext_emails, r.Email)
            } else {
                encrypted_emails = append(encrypted_emails, r.Email)
            }
        }

        if len(to_emails) == 0 {
            log.Println("Tried to send an email without to recipients")
            responder.WriteError("No recipients specified")
            return
        }

        if len(plaintext_emails) > 0 && send_request.PlaintextBody == "" {
            log.Println("No body provided for unencrypted recipients")
            responder.WriteError("No plaintext body for outbounds recipients")
            return
        }
        
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
            log.Println("Bad boundary format: ", send_request.Boundary)
            responder.WriteError("Bad boundary format")
            return
        }

        if send_request.ContentType == "multipart/mixed" || send_request.ContentType == "multipart/alternative" {
            headers += fmt.Sprintf("Content-Type: %s; boundary=%s", send_request.ContentType, send_request.Boundary)
        }

        if len(plaintext_emails) > 0 {
            go send_outbound_emails()
        }

        email := mongo_schemes.Email{
            Id: email_id,
            From: user.MainEmail,
            DHPublicKey: send_request.PublicKey,
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

        estimated_size := int64(len(email_bson)) + *metadata_size

        raw_email := bson.Raw(email_bson)

        if send_request.DraftId != "" {
            draft_id, err := primitive.ObjectIDFromHex(send_request.DraftId)
            if err != nil {
                log.Println("Error decoding draft id", err)
                responder.WriteError("Malformed request")
                return
            }

            filter := bson.D{{Key: "_id", Value: draft_id}}
            var draft_metadata mongo_schemes.Metadata
            err = metadata_collection.FindOneAndDelete(context.TODO(), filter).Decode(&draft_metadata)
            if err != nil {
                log.Println("Error deleting metadata", err)
                responder.WriteError("Server error")
                return
            }

            email_id = draft_metadata.EmailID
            email_filter := bson.D{{Key: "_id", Value: draft_metadata.EmailID}}
            update_field := bson.M{
                    "from": email.From,
                    "dh_public": send_request.PublicKey,
                    "encryption": send_request.Encryption,
                    "body": send_request.Body,
                    "headers": headers,
            }
            if draft_metadata.Attachment {
                update_field["attachment"] = true
            }
            update := bson.D{{Key: "$set", Value: update_field}}

            var draft_email mongo_schemes.Email
            err = email_collection.FindOneAndUpdate(context.TODO(), email_filter, update).Decode(&draft_email)
            if err != nil {
                log.Println("Error updating draft", err)
                responder.WriteError("Server error")
                return
            }
            estimated_size += draft_email.AttachmentSize
        } else {
            _, err = email_collection.InsertOne(context.Background(), raw_email)

            if err != nil {
                log.Println("There was an error creating the email:", err.Error())
                responder.WriteError("Server error")
                return
            }
        }

        var metadata []interface{}
        for _, u := range send_request.To {
            m := mongo_schemes.Metadata{
                UsedAddress: u.Email,
                Size: estimated_size,
                KeyUsed: u.KeyUsed,
                EncryptedKey: u.EncryptedKey,
                Ciphertext: u.Ciphertext,
                Salt: u.Salt,
                EmailID: email_id,
                Subject: send_request.Subject,
                MessageId: message_id,
                From: user.MainEmail,
                Private: true,
            }
            if u.Sender {
                m.Sent = true
            }
            metadata = append(metadata, m)
        }

        _, err = metadata_collection.InsertMany(context.Background(), metadata)
        if err != nil {
            log.Println("There was an error creating the email metadata:", err.Error())
            responder.WriteError("Server error")
            return
        }

        // err = usage.IncrementUsageSize(context.TODO(), usage_collection, encrypted_emails, estimated_size) // Update other users
        // if err != nil {
        //     log.Println("Error updating used size:", err.Error())
        //     responder.WriteError("Server error")
        //     return
        // }
        //
        // err = usage.IncrementSentUsage(context.TODO(), usage_collection, user.Usage, estimated_size)
        // if err != nil {
        //     log.Println("Error updating usage for sender: ", err.Error())
        //     responder.WriteError("Server error")
        //     return
        // }

        responder.WriteData("Email sent correctly")
    })
}

type StoreDraftRequest struct {
    Encryption int `json:"encryption"`
    KeyUsed []byte `json:"key_used"`
    EncryptedKey []byte `json:"encrypted_key"`
    Salt []byte `json:"salt"`
    To []string `json:"to"`
    CC []string `json:"cc"`
    BCC []string `json:"bcc"`
    Subject string `json:"subject"`
    Body []byte `json:"body"`
    ContentType string `json:"content_type"`
    Boundary string `json:"boundary"`
    InReplyTo string `json:"in_reply_to"`
    References string `json:"references"`
    DraftId string `json:"draft_id"`
}

func StoreDraft(users_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection, usage_collection *mongo.Collection, metadata_size *int64) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        tracked_usage, err := usage.GetUsage(context.TODO(), usage_collection, user.MainEmail)
        if err != nil {
            log.Println("Error retrieving usage:", err.Error())
            responder.WriteError("Server error")
            return
        }

        if tracked_usage.UsedSpace >= user.PlanConfig.SpaceLimit {
            responder.WriteError("You can't send or recieve, you don't have storage")
            return
        }

        store_draft_request, err := api_utils.DecodeJson[StoreDraftRequest](r.Body)
        if err != nil {
            log.Println("Error decoding request:", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        var to_emails []EncryptRecipient
        var cc_emails []EncryptRecipient
        for _, r := range store_draft_request.To {
            to_emails = append(to_emails, EncryptRecipient{Email: r})
        }
        for _, r := range store_draft_request.CC {
            cc_emails = append(cc_emails, EncryptRecipient{Email: r})
        }
        
        email_id := primitive.NewObjectID()
        message_id := fmt.Sprintf("<%s@secria.me>", email_id.Hex()) // Change when more domains are allowed

        headers := fmt.Sprintf("From: \"%s\" <%s>\r\n", user.Name, user.MainEmail)
        headers += fmt.Sprintf("To:%s\r\n", list_email_header_format(to_emails))
        if len(cc_emails) != 0 {
            headers += fmt.Sprintf("CC:%s\r\n", list_email_header_format(cc_emails)) // First space is included in the function
        }
        if len(store_draft_request.Subject) != 0 {
            headers += fmt.Sprintf("Subject: %s\r\n", store_draft_request.Subject)
        }
        headers += fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z))
        headers += fmt.Sprintf("Message-Id: %s\r\n", message_id)

        if store_draft_request.InReplyTo != "" {
            headers += fmt.Sprintf("In-Reply-To: %s", store_draft_request.InReplyTo)
            if store_draft_request.References != "" {
                headers += fmt.Sprintf("References: %s %s", store_draft_request.InReplyTo, store_draft_request.References)
            }
        }

        if !check_valid_boundary(store_draft_request.Boundary) {
            log.Println("Bad boundary format: ", store_draft_request.Boundary)
            responder.WriteError("Bad boundary format")
            return
        }

        if store_draft_request.ContentType == "multipart/mixed" || store_draft_request.ContentType == "multipart/alternative" {
            headers += fmt.Sprintf("Content-Type: %s; boundary=%s", store_draft_request.ContentType, store_draft_request.Boundary)
        }

        email := mongo_schemes.Email{
            Id: email_id,
            From: user.MainEmail,
            Encryption: mongo_schemes.Encryption_ECDH_MLKEM,
            Body: store_draft_request.Body,
            Headers: headers,
        }

        email_bson, err := bson.Marshal(email)
        if err != nil {
            log.Println("There was an error creating the email:", err.Error())
            responder.WriteError("Server error")
            return
        }

        estimated_size := int64(len(email_bson)) + *metadata_size

        raw_email := bson.Raw(email_bson)

        if store_draft_request.DraftId != "" {
            draft_id, err := primitive.ObjectIDFromHex(store_draft_request.DraftId)
            if err != nil {
                log.Println("Error decoding draft id", err)
                responder.WriteError("Malformed request")
                return
            }

            filter := bson.D{{Key: "_id", Value: draft_id}}
            var draft_metadata mongo_schemes.Metadata
            err = metadata_collection.FindOneAndDelete(context.TODO(), filter).Decode(&draft_metadata)
            if err != nil {
                log.Println("Error deleting metadata", err)
                responder.WriteError("Server error")
                return
            }

            email_id = draft_metadata.EmailID
            email_filter := bson.D{{Key: "_id", Value: draft_metadata.EmailID}}
            update_field := bson.M{
                    "from": email.From,
                    "encryption": store_draft_request.Encryption,
                    "body": store_draft_request.Body,
                    "headers": headers,
            }
            if draft_metadata.Attachment {
                update_field["attachment"] = true
            }
            update := bson.D{{Key: "$set", Value: update_field}}
            var draft_email mongo_schemes.Email
            err = email_collection.FindOneAndUpdate(context.TODO(), email_filter, update).Decode(&draft_email)
            if err != nil {
                log.Println("Error updating draft", err)
                responder.WriteError("Server error")
                return
            }
            estimated_size += draft_email.AttachmentSize
        } else {
            _, err = email_collection.InsertOne(context.Background(), raw_email)

            if err != nil {
                log.Println("There was an error creating the email:", err.Error())
                responder.WriteError("Server error")
                return
            }
        }

        m := mongo_schemes.Metadata{
            UsedAddress: user.MainEmail,
            Size: estimated_size,
            KeyUsed: store_draft_request.KeyUsed,
            EncryptedKey: store_draft_request.EncryptedKey,
            Salt: store_draft_request.Salt,
            EmailID: email_id,
            Subject: store_draft_request.Subject,
            MessageId: message_id,
            From: user.MainEmail,
            Draft: true,
        }

        res, err := metadata_collection.InsertOne(context.Background(), m)
        if err != nil {
            log.Println("There was an error creating the email metadata:", err.Error())
            responder.WriteError("Server error")
            return
        }
        metadata_id := res.InsertedID.(primitive.ObjectID)

        // err = usage.IncrementUsageSize(context.TODO(), usage_collection, encrypted_emails, estimated_size) // Update other users
        // if err != nil {
        //     log.Println("Error updating used size:", err.Error())
        //     responder.WriteError("Server error")
        //     return
        // }
        //
        // err = usage.IncrementSentUsage(context.TODO(), usage_collection, user.Usage, estimated_size)
        // if err != nil {
        //     log.Println("Error updating usage for sender: ", err.Error())
        //     responder.WriteError("Server error")
        //     return
        // }


        responder.WriteData(metadata_id.Hex())
    })
}

type CreateEmptyDraftRequest struct {
    Encryption int `json:"encryption"`
    KeyUsed []byte `json:"key_used"`
    EncryptedKey []byte `json:"encrypted_key"`
    Salt []byte `json:"salt"`
}

func CreateEmptyDraft(metadata_collection *mongo.Collection, email_collection *mongo.Collection, usage_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        tracked_usage, err := usage.GetUsage(context.TODO(), usage_collection, user.MainEmail)
        if err != nil {
            log.Println("Error retrieving usage:", err.Error())
            responder.WriteError("Server error")
            return
        }

        if tracked_usage.UsedSpace >= user.PlanConfig.SpaceLimit {
            responder.WriteError("You don't have space left")
            return
        }

        request, err := api_utils.DecodeJson[CreateEmptyDraftRequest](r.Body)

        email := mongo_schemes.Email{
            Encryption: request.Encryption,
            AttachmentSize: 0,
            From: user.MainEmail,
        }

        inserted, err := email_collection.InsertOne(context.TODO(), email)
        if err != nil {
            log.Println("Failed to create email", err)
            responder.WriteError("Server error")
            return
        }

        inserted_id := inserted.InsertedID.(primitive.ObjectID)

        metadata := mongo_schemes.Metadata{
            UsedAddress: user.MainEmail,
            From: user.MainEmail,
            KeyUsed: request.KeyUsed,
            EncryptedKey: request.EncryptedKey,
            Salt: request.Salt,
            EmailID: inserted_id,
            Attachment: true,
            Draft: true,
        }

        inserted_metadata_id, err := metadata_collection.InsertOne(context.TODO(), metadata)
        if err != nil {
            log.Println("Error creating metadata")
            responder.WriteError("Server error")
            return
        }

        metadata_id := inserted_metadata_id.InsertedID.(primitive.ObjectID)

        responder.WriteData(metadata_id.Hex())
    })
}

func UploadFile(minio_client *minio.Client, bucket_name string, metadata_collection *mongo.Collection, email_collection *mongo.Collection, usage_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)

        user := r.Context().Value("user").(mongo_schemes.User)

        tracked_usage, err := usage.GetUsage(context.TODO(), usage_collection, user.MainEmail)
        if err != nil {
            log.Println("Error retrieving usage:", err.Error())
            responder.WriteError("Server error")
            return
        }

        if tracked_usage.UsedSpace >= user.PlanConfig.SpaceLimit {
            responder.WriteError("You don't have space left")
            return
        }

        err = r.ParseMultipartForm(25 << 20) // Max size is 25MB
        if err != nil {
            log.Println("Error decoding multipart form", err)
            responder.WriteError("File too big, max is 25Mb")
            return
        }

        draft_id_string := r.FormValue("draft_id")
        if draft_id_string == "" {
            log.Println("Draft id is empty")
            responder.WriteError("Bad parameters")
            return
        } else {
            draft_id, err := primitive.ObjectIDFromHex(draft_id_string)
            if err != nil {
                log.Println("Error decoding id", err)
                responder.WriteError("Bad parameters")
                return
            }


            file, handler, err := r.FormFile("file")
            if err != nil {
                log.Println("Error getting uploaded file", err)
                responder.WriteError("Server error")
                return
            }
            defer file.Close()

            uuid := uuid.New().String()
            size := int64(handler.Size)
            _, err = minio_client.PutObject(context.TODO(), bucket_name, uuid, file, size, minio.PutObjectOptions{})
            if err != nil {
                log.Println("Error uploading attachment", err)
                responder.WriteError("Server error")
                return
            }

            a := mongo_schemes.Attachment{
                Filename: handler.Filename,
                ContentType: handler.Header.Get("Content-Type"),
                Size: size,
                Reference: uuid,
            }

            filter := bson.D{{Key: "_id", Value: draft_id}}
            email, err := getEmailByFilter(context.TODO(), metadata_collection, filter)
            if err != nil {
                log.Println("Error getting email", err)
                responder.WriteError("Server error")
                return
            }

            if email.Email.AttachmentSize + size > 25 << 20 {
                log.Println("Tried to upload an attachment that is too big", err)
                responder.WriteError("Attachments size more than 25MB")
                return
            }

            update := bson.D{
                {Key: "$push", Value: bson.M{"attachments": a}},
                {Key: "$inc", Value: bson.M{"attachment_size": size}},
            }
            _, err = email_collection.UpdateByID(context.TODO(), email.Email.Id, update)

            if err != nil {
                log.Println("Error updating attachments", err)
                responder.WriteError("Server error")
                return
            }

            responder.WriteData(uuid)
        }
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
    return email == "secria.me"
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

// func SendPublic(users_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection) http.Handler {
//     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//         responder := api_utils.NewJsonResponder[string](w)
//         user := r.Context().Value("user").(mongo_schemes.User)
//
//         var send_request SendPublicRequest
//         if err := json.NewDecoder(r.Body).Decode(&send_request); err != nil {
//             log.Println("Error decoding request: "+err.Error())
//             responder.WriteError("Invalid request body")
//             return
//         }
//
//         valid_addresses := append(user.Addresses, user.MainEmail)
//
//         if !slices.Contains(valid_addresses, send_request.Address) {
//             log.Println("Subaddress was not found")
//             responder.WriteError("Subaddress was not found")
//             return
//         }
//
//         to_length := len(send_request.To)
//         cc_length := len(send_request.CC)
//         bcc_length := len(send_request.BCC)
//         length := to_length + cc_length + bcc_length + 1
//
//         var users []RecipientDomainWrapper = make([]RecipientDomainWrapper, 0, length)
//         for i, address := range send_request.To {
//             username, domain, err := split_user_domain(address)
//             if err != nil {
//                 log.Println("Malformed address: "+address)
//                 responder.WriteError("Malformed address:", address)
//                 return
//             }
//             recipient := RecipientDomainWrapper{
//                 Recipient: Recipient{
//                     Email: address,
//                 },
//                 Username: username,
//                 Domain: domain,
//             }
//             if i < to_length {
//                 recipient.To = true
//             } else if i < cc_length {
//                 recipient.CC = true
//             } else if i < bcc_length {
//                 recipient.BCC = true
//             } else {
//                 recipient.Sender = true
//             }
//             users = append(users, recipient)
//         }
//
//         users_by_domain := groupBy(func(i int, v RecipientDomainWrapper) string  { return v.Domain}, users)
//
//         var owned_domain_users []RecipientDomainWrapper = make([]RecipientDomainWrapper, 0)
//         var outbound_domains []string = make([]string, 0)
//         for d, v := range users_by_domain {
//             if check_domain_ownership(d) {
//                 for _, u := range v {
//                     username, subaddress, err := split_user_sub(u.Username)
//                     if err != nil {
//                         log.Println("There was an error parsing the username: "+err.Error())
//                         responder.WriteError("Malformed secria user recipient")
//                         return
//                     }
//                     u.Username = username
//                     u.Subaddress = subaddress
//                     owned_domain_users = append(owned_domain_users, u)
//                 }
//             } else {
//                 outbound_domains = append(outbound_domains, d)
//             }
//         }
//
//         // from := user.Username + "+" + send_request.Address + "@" + user.Domain;
//         from := user.MainEmail // This is wrong
//
//         headers := "From: " + send_request.Address + "\r\n"
//         headers += "To" + strings.Join(send_request.To, ", ") + "\r\n"
//         headers += "CC" + strings.Join(send_request.CC, ", ") + "\r\n"
//         headers += "Subject" + send_request.Subject + "\r\n"
//         headers += "\r\n"
//
//         body := headers + send_request.Body
//
//         owned_channel := store_owned_messages(context.Background(), users_collection, metadata_collection, email_collection, from, owned_domain_users, body)
//
//         outbound_channels := make([]chan error, 0)
//         for k, v := range users_by_domain {
//             // ch := send_emails_to_domain(from, v, k, []byte(message))
//             ch := send_emails_to_domain(from, v, k, []byte(body))
//             outbound_channels = append(outbound_channels, ch)
//         }
//
//         err := <- owned_channel
//         if err != nil {
//             log.Println("There was an error creating the public email: "+err.Error())
//             responder.WriteError("Server error")
//             return
//         }
//
//         for _, ch := range outbound_channels {
//             err := <- ch
//             if err != nil {
//                 log.Println("There was an error sending the public email: "+err.Error())
//                 responder.WriteError("Failed to connect to domain")
//                 return
//             }
//         }
//
//         responder.WriteData("Email sent correctly")
//     })
// }

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

        failed := false
        outer:
        for _, tag := range tag_request.Tags {
            for _, user_tag := range user.Tags {
                if user_tag.Name == tag {
                    continue outer
                }
            }
            failed = true
            break
        }
        if failed {
            log.Println("User tried to set a non existing tag: ", tag_request.Tags)
            responder.WriteError("Invalid tag")
            return
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
            log.Println("Failed to update email: ", err.Error())
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

        delete_email_request, err := api_utils.DecodeJson[DeleteEmailRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse mark read request: ", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        filter := bson.M{"_id": bson.M{"$in": delete_email_request.EmailID}}
        update := bson.D{{Key: "$set", Value: bson.M{
            "deleted": true,
        }}}

        _, err = metadata_collection.UpdateMany(context.TODO(), filter, update)
        if err != nil {
            log.Println("Failed to set deleted tag: "+err.Error())
            responder.WriteError("Failed to delete")
            return
        }

        responder.WriteData("Deleted emails")
    })
}

type RestoreEmailRequest struct {
    EmailId []primitive.ObjectID `json:"email_id"`
}

func RestoreEmails(metadata_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)

        restore_email_request, err := api_utils.DecodeJson[DeleteEmailRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse mark read request: ", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        filter := bson.M{"_id": bson.M{"$in": restore_email_request.EmailID}}
        update := bson.D{{Key: "$unset", Value: bson.M{
            "deleted": true,
        }}}

        _, err = metadata_collection.UpdateMany(context.TODO(), filter, update)
        if err != nil {
            log.Println("Failed to remove deleted tag: "+err.Error())
            responder.WriteError("Failed to restore")
            return
        }

        responder.WriteData("Restored emails")
    })
}
