package totp

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"secria_api/internal/api_utils"
	"secria_api/internal/redis_handler"
	"shared/mongo_schemes"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type GenerateTOTPResponse struct {
    URL string `json:"url"`
    Secret string `json:"secret"`
}

func GenerateTOTP(client *redis.Client) http.HandlerFunc {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user").(mongo_schemes.User)
        responder := api_utils.NewJsonResponder[GenerateTOTPResponse](w)

        secret, err := totp.Generate(totp.GenerateOpts{
            Issuer: "secria.me",
            AccountName: user.MainEmail,
        })

        if err != nil {
            responder.WriteError("Couldn't generate secret")
            return
        }

        url_secret := secret.URL()
        base32_secret := secret.Secret()

        err = client.Set(context.TODO(), user.Id.Hex(), base32_secret, time.Minute * 2).Err()
        if err != nil {
            responder.WriteError("Server error")
            return
        }

        responder.WriteData(GenerateTOTPResponse{
            URL: url_secret,
            Secret: base32_secret,
        })
    })
}

type CodeRequest struct {
    Code string `json:"code"`
}

func InitialValidateTOTP(client *redis.Client, user_collection *mongo.Collection) http.HandlerFunc {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user").(mongo_schemes.User)
        responder := api_utils.NewJsonResponder[string](w)

        code, err := api_utils.DecodeJson[CodeRequest](r.Body)
        if err != nil {
            log.Println("Malformed request: ", err.Error())
            responder.WriteError("Malformed request")
            return 
        }

        secret, err := client.Get(context.TODO(), user.Id.Hex()).Result()
        if err != nil {
            log.Println("Failed to get user secret", err.Error())
            responder.WriteError("Server error")
            return
        }

        valid := totp.Validate(code.Code, secret)
        if !valid {
            log.Println("An invalid totp was provided")
            responder.WriteError("Invalid code")
            return
        }

        err = client.Del(context.TODO(), user.Id.Hex()).Err()
        if err != nil {
            log.Println("Couldn't delete mfa attempt", err.Error())
            responder.WriteError("Server error")
            return
        }

        update := bson.D{{Key: "$set", Value: bson.M{"totp_active": true, "totp_secret": secret}}}

        _, err = user_collection.UpdateByID(context.TODO(), user.Id, update)
        if err != nil {
            log.Println("Failed to update user", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Validated code")
    })
}

func DisableTOTP(user_collection *mongo.Collection) http.HandlerFunc {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user").(mongo_schemes.User)
        responder := api_utils.NewJsonResponder[string](w)

        code, err := api_utils.DecodeJson[CodeRequest](r.Body)
        if err != nil {
            log.Println("Malformed request: ", err.Error())
            responder.WriteError("Malformed request")
            return
        }

        valid := totp.Validate(code.Code, user.TOTPSecret)
        if !valid {
            log.Println("Invalid TOTP code")
            responder.WriteError("Invalid TOTP code")
            return
        }

        update := bson.D{{Key: "$unset", Value: bson.M{"totp_active": true, "totp_secret": true}}}
        _, err = user_collection.UpdateByID(context.TODO(), user.Id, update)
        if err != nil {
            log.Println("Failed to update user: ", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Disabled MFA")
    })
}

type StoredMfaAttempt struct {
    Request string `json:"request"`
    Attempts int `json:"attempts"`
}

func addAttemptToSession(ctx context.Context, mfa_attempt_client *redis.Client, user_id primitive.ObjectID, prev_request StoredMfaAttempt) error {
    new_request := prev_request
    new_request.Attempts += 1

    new_request_encoded, err := json.Marshal(new_request)
    if err != nil {
        return err
    }

    mfa_attempt_client.Set(ctx, user_id.Hex(), new_request_encoded, time.Minute * 5)
    return nil
}

func LoginCheckTOTP(cookie_client *redis.Client, mfa_attempt_client *redis.Client, user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user").(mongo_schemes.User)
        responder := api_utils.NewJsonResponder[api_utils.LoginResponse](w)

        code, err := api_utils.DecodeJson[CodeRequest](r.Body)
        if err != nil {
            log.Println("Malformed request: ", err.Error())
            responder.WriteError("Malformed request")
            return
        }

        stored_data, err := mfa_attempt_client.Get(context.TODO(), user.Id.Hex()).Result()
        if err != nil {
            log.Println("Couldn't retrieve mfa attempt: ", err.Error())
            responder.WriteError("MFA attempt not found")
            return
        }

        mfa_attempt, err := api_utils.UnmarshalJson[StoredMfaAttempt]([]byte(stored_data))
        if err != nil {
            log.Println("Failed to decode mfa attempt: ", err.Error())
            responder.WriteError("Server error")
            return
        }


        if mfa_attempt.Attempts >= 5 {
            log.Println("Attempt limit overpassed")
            responder.WriteError("Too many attempts")
            return
        }

        if mfa_attempt.Request != "login" {
            log.Println("This mfa request is not for login: ", mfa_attempt.Request)
            responder.WriteError("Invalid session")
            return
        }

        valid := totp.Validate(code.Code, user.TOTPSecret)
        if !valid {
            log.Println("Invalid code provided for login")
            responder.WriteError("Invalid code")
            go addAttemptToSession(context.TODO(), mfa_attempt_client, user.Id, mfa_attempt)
            return
        }

        err = mfa_attempt_client.Del(context.TODO(), user.Id.Hex()).Err()
        if err != nil {
            log.Println("Couldn't delete mfa attempt", err.Error())
            responder.WriteError("Server error")
            return
        }

        cookie, err := redis_handler.GenerateCookie(cookie_client, user.Id)
        if err != nil {
            log.Println("There was an error generating the cookie: ", err.Error())
            responder.WriteError("Authentication failed")
            return
        }

        http.SetCookie(w, &cookie)

        if user.Contacts == nil {
            responder.WriteData(api_utils.LoginResponse{
                User: user,
                Contacts: []api_utils.ContactResponse{},
            })
            return
        }

        contacts, err := api_utils.RetrieveContacts(context.Background(), user_collection, user.Contacts)
        if err != nil {
            log.Println("There was an error retrieving the contacts: ", err.Error())
            responder.WriteError("Authentication failed")
            return
        }

        responder.WriteData(api_utils.LoginResponse{
            User: user,
            Contacts: contacts,
        })
    })
}

func ValidateTOTP(code string, secret string) bool {
    return totp.Validate(code, secret)
}
