package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"secria_api/internal/api_utils"
	"secria_api/internal/plans_handler"
	"secria_api/internal/redis_handler"
	"secria_api/internal/totp"
	"shared/mongo_schemes"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/argon2"
)

func argonHash(password string, salt []byte) []byte {
	time := uint32(1)          // Number of iterations
	memory := uint32(64 * 1024) // Memory usage in KiB (64 MiB)
	threads := uint8(4)        // Number of threads
	keyLength := uint32(32)    // Desired hash length in bytes
	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLength)
    return hash
}

func hashString(password string) (string, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }

    hash := argonHash(password, salt)
	saltBase64 := base64.StdEncoding.EncodeToString(salt)
	hashBase64 := base64.StdEncoding.EncodeToString(hash)

	return fmt.Sprintf("%s$%s", saltBase64, hashBase64), nil
}

func validateHash(stored_password, check_password string) error {
    parts := strings.Split(stored_password, "$")
    if len(parts) != 2 {
        return fmt.Errorf("stored password doesn't fullfill the format") 
    }
    
    salt, err := base64.StdEncoding.DecodeString(parts[0])
    if err != nil {
        return err
    }

    expectedHash, err := base64.StdEncoding.DecodeString(parts[1])
    if err != nil {
        return err
    }
    
    computedHash := argonHash(check_password, salt)

    if subtle.ConstantTimeCompare(expectedHash, computedHash) != 1 {
        return fmt.Errorf("passwords don't match")
    }
    return nil
}

type LoginRequest struct {
    Email string `json:"email"`
    Password string `json:"password"`
}

func Login(user_collection *mongo.Collection, redis_client *redis.Client) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[api_utils.LoginResponse](w)
        var login_request LoginRequest
        if err := json.NewDecoder(r.Body).Decode(&login_request); err != nil {
            log.Println("Error decoding request:", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        filter := bson.D{{ Key: "email", Value: login_request.Email }}
        var user mongo_schemes.User
        err := user_collection.FindOne(context.Background(), filter).Decode(&user)

        if err != nil {
            log.Println("Error finding user:", err.Error())
            responder.WriteError("Authentication failed")
            return
        }

        err = validateHash(user.Password, login_request.Password)
        if err != nil {
            log.Println("There was an error validating the password:", err.Error())
            responder.WriteError("Authentication failed")
            return
        }

        if user.TOTPActive {
            _, err := redis_client.Get(context.TODO(), fmt.Sprintf("mfa:%s", user.Id.Hex())).Result()
            if err == redis.Nil {
                attempt := totp.StoredMfaAttempt{
                    Request: "login",
                    Attempts: 0,
                }
                encoded_attempt, err := json.Marshal(attempt)
                if err != nil {
                    log.Println("Error marshaling mfa attempt: ", err.Error())
                    responder.WriteError("Server error")
                    return
                }
                redis_client.Set(context.TODO(), fmt.Sprintf("mfa:%s", user.Id.Hex()), string(encoded_attempt), time.Minute * 5)
            } else if err != nil {
                log.Println("Error retrieving stored attempt", err.Error())
                responder.WriteError("Server error")
                return
            }
            responder.WriteError("MFA")
            return
        }

        log.Println("User logged in: ", login_request.Email)

        cookie, err := redis_handler.GenerateCookie(redis_client, user.Id)
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

func CheckAuth(redis_client *redis.Client, user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[api_utils.LoginResponse](w)
        session_cookie, err := r.Cookie("session")
        if err != nil {
            log.Println("Check auth failed:", err.Error())
            responder.WriteError("Failed")
            return
        }

        cookie_object, err := redis_handler.GetCookieObject(redis_client, session_cookie.Value)
        user, err := redis_handler.GetUserFromCookie(user_collection, cookie_object)

        if err != nil {
            log.Println("Failed to find user from cookie:", err.Error())
            responder.WriteError("Failed")
            return
        }

        if user.Contacts == nil {
            responder.WriteData(api_utils.LoginResponse{
                User: user,
                Contacts: []api_utils.ContactResponse{},
            })
            return
        }

        contacts, err := api_utils.RetrieveContacts(context.Background(), user_collection, user.Contacts)
        if err != nil {
            log.Println("There was an error retrieving the contacts:", err.Error())
            responder.WriteError("Authentication failed")
            return
        }

        responder.WriteData(api_utils.LoginResponse{
            User: user,
            Contacts: contacts,
        })
    })
}

type RegisterRequest struct {
    Name string `json:"name"`
    Username string `json:"username"`
    Domain string `json:"domain"`
    Password string `json:"password"`
    Captcha string `json:"captcha"`
    KeyId []byte `json:"key_id"`
    DHPublicKey []byte `json:"dh_pub"`
    DHPrivateKey []byte `json:"dh_priv"`
    MLKEMPublicKey []byte `json:"mlkem_pub"`
    MLKEMPrivateKey []byte `json:"mlkem_priv"`
    SentKey []byte `json:"sent_key"`
}

type RecaptchaResponse struct {
    Success bool `json:"success"`
    ChallengeTS string `json:"challenge_ts"`
    Hostname string `json:"hostname"`
    ErrorCodes []string `json:"error-codes"`
}

var valid_user_regex = regexp.MustCompile(`^[a-zA-Z0-9]{3,}$`)

func check_valid_username(username string) bool {
    return valid_user_regex.Match([]byte(username))
}

func check_valid_domain(domain string) bool {
    return domain == "secria.me"
}

const CAPTCHA_URL = "https://www.google.com/recaptcha/api/siteverify"

func Register(env string, user_collection *mongo.Collection, usage_collection *mongo.Collection, captcha_secret string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        var register_request RegisterRequest
        if err := json.NewDecoder(r.Body).Decode(&register_request); err != nil {
            log.Println("Error decoding request: "+err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        if !check_valid_domain(register_request.Domain) {
            log.Println("Invalid domain:", register_request.Domain)
            responder.WriteError("Invalid domain")
            return
        }

        if !check_valid_username(register_request.Username) {
            log.Println("Invalid username:", register_request.Username)
            responder.WriteError("Invalid username")
            return
        }

        email := fmt.Sprintf("%s@secria.me", register_request.Username)

        log.Println("Registering user:", email)
        filter := bson.D{{Key: "email", Value: email}}
        var user mongo_schemes.User
        err := user_collection.FindOne(context.Background(), filter).Decode(&user)

        if err == nil {
            log.Println("Email already in use, name and domain:", register_request.Name, ",", register_request.Domain)
            responder.WriteError("Email already in use")
            return
        } else if (err != mongo.ErrNoDocuments) {
            log.Println("Error in register: "+err.Error())
            responder.WriteError("An error has ocurred")
            return
        }

        if env != "DEV" {
            data := url.Values{}
            data.Set("secret", captcha_secret)
            data.Set("response", register_request.Captcha)

            resp, err := http.PostForm(CAPTCHA_URL, data)
            if err != nil {
                log.Println("Captcha failed:", err.Error())
                responder.WriteError("An error has ocurred")
                return
            }
            defer resp.Body.Close()

            var recaptchaResponse RecaptchaResponse
            if err := json.NewDecoder(resp.Body).Decode(&recaptchaResponse); err != nil {
                log.Println("Captcha failed:", err.Error())
                responder.WriteError("Captcha failed")
                return
            }

            log.Println("Captcha result:", recaptchaResponse.Success)

            if !recaptchaResponse.Success {
                log.Println("Captcha failed:", strings.Join(recaptchaResponse.ErrorCodes, ", "))
                responder.WriteError("Captcha failed")
                return
            }
        }

        res, err := usage_collection.InsertOne(context.TODO(), mongo_schemes.TrackedUsage{Email: email})
        if err != nil {
            log.Println("Failed to insert usage into collection: ", err.Error())
            responder.WriteError("Server error")
            return
        }

        usage_id := res.InsertedID.(primitive.ObjectID)

        hash, err := hashString(register_request.Password)
        if err != nil {
            log.Println("Error hashing password: ", err.Error())
            responder.WriteError("Server error")
            return
        }

        _, err = user_collection.InsertOne(context.TODO(), mongo_schemes.User{
            Name: register_request.Name,
            MainEmail: email,
            Addresses: []string{email},
            Password: hash,
            MainKey: mongo_schemes.ECDH_MLKEM_KEY{
                Key: mongo_schemes.Key{
                    KeyId: register_request.KeyId,
                    Encryption: mongo_schemes.Encryption_ECDH_MLKEM,
                },
                MLKEMPublicKey: register_request.MLKEMPublicKey,
                MLKEMPrivateKey: register_request.MLKEMPrivateKey,
                DHPublicKey: register_request.DHPublicKey,
                DHPrivateKey: register_request.DHPrivateKey,
                SentKey: register_request.SentKey,
            },
            PlanConfig: plans_handler.FreePlanOptions,
            Usage: usage_id,
        })

        if err != nil {
            log.Println("Failed to insert user:", err.Error())
            responder.WriteError("Failed to create user")
            return
        }

        responder.WriteData("User created")
    })
}

func Logout(w http.ResponseWriter, r *http.Request) {
        cookie := http.Cookie{
            Name: "session_jwt",
            Expires: time.Unix(0, 0),
            MaxAge: -1,
            HttpOnly: true,
            Secure: true,
            SameSite: http.SameSiteLaxMode,
            Path: "/",
            //Domain: DOMAIN,
        }
        http.SetCookie(w, &cookie)
}
