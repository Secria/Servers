package user

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"secria_api/internal/api_utils"
	"secria_api/internal/redis_handler"
	"shared/mongo_schemes"
	"slices"
	"strings"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func GenerateAddContactCode(redis_client *redis.Client) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        code, err := redis_handler.GenerateShareCode(redis_client, user.Id)
        if err != nil {
            log.Println("There was an error creating the code:", err.Error())
            responder.WriteError("Error generating code")
            return
        }

        responder.WriteData(code)
    })
}

type AddContactRequest struct {
    Code string `json:"code"`
}

func AddContact(redis_client *redis.Client, user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[api_utils.ContactResponse](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        request_code, err := api_utils.DecodeJson[AddContactRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse add contact request: ", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        code_user, err := redis_handler.GetUserFromSharedCode(redis_client, user_collection, request_code.Code)
        if err != nil {
            log.Println("There was an error retrieving the user from the code:", err.Error())
            responder.WriteError("Invalid code")
            return
        }

        update := bson.D{{Key: "$addToSet", Value: bson.D{{Key: "contacts", Value: code_user.MainEmail}}}}
        _, err = user_collection.UpdateByID(context.Background(), user.Id, update)
        if err != nil {
            log.Println("Error updating user: "+err.Error())
            responder.WriteError("Server error")
            return
        }

        update = bson.D{{Key: "$addToSet", Value: bson.D{{Key: "contacts", Value: user.MainEmail}}}}
        _, err = user_collection.UpdateByID(context.Background(), code_user.Id, update)
        if err != nil {
            log.Println("Error updating user:", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData(api_utils.ContactResponse{
            Name: code_user.Name,
            Email: code_user.MainEmail,
            MLKEMPublicKey: code_user.MainKey.MLKEMPublicKey,
            DHPublicKey: code_user.MainKey.DHPublicKey,
        })
    })
}

type RemoveContactRequest struct {
    Email string `json:"email"`
}

func DeleteContact(user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        remove_contact_request, err := api_utils.DecodeJson[RemoveContactRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse remove contact request: ", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        if !slices.Contains(user.Contacts, remove_contact_request.Email) {
            log.Println("Address was not found in contacts")
            responder.WriteError("You don't have this address in contacts")
            return
        }

        update := bson.D{{Key: "$pull", Value: bson.D{{Key: "contacts", Value: remove_contact_request.Email}}}}
        _, err = user_collection.UpdateByID(context.Background(), user.Id, update)
        if err != nil {
            log.Println("Error updating user: ", err.Error())
            responder.WriteError("Server error")
            return
        }

        filter := bson.D{{Key: "email", Value: remove_contact_request.Email}}
        update = bson.D{{Key: "$pull", Value: bson.D{{Key: "contacts", Value: user.MainEmail}}}}
        _, err = user_collection.UpdateOne(context.Background(), filter, update)
        if err != nil {
            log.Println("Error updating user:", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Deleted user")
    })
}

var valid_address_regex = regexp.MustCompile(`^[a-zA-Z0-9]{3,20}$`)

func check_valid_address(address string) bool {
    return valid_address_regex.Match([]byte(address))
}

var charset = "abcdefghijklmnopqrstuvwxyz"

func randomString(n int) (string, error) {
    randomBytes := make([]byte, n)
    for i := range randomBytes {
        val, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
        if err != nil {
            return "", err
        }
        randomBytes[i] = charset[val.Int64()]
    }
    return string(randomBytes), nil
}

type AddressRequest struct {
    Address string `json:"address"`
}

func AddNewAddress(user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        if len(user.Addresses) >= user.PlanConfig.AddressLimit {
            responder.WriteError("You can't add more addresses to your current plan")
            return
        }

        add_address_request, err := api_utils.DecodeJson[AddressRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse edit keys request:", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        if !check_valid_address(add_address_request.Address) {
            log.Println("Invalid address")
            responder.WriteError("Invalid address")
            return
        }

        var random_address string
        for {
            random, err := randomString(5)
            if err != nil {
                responder.WriteError("Server error")
            }
            random_address = fmt.Sprintf("%s.%s@secria.me", add_address_request.Address, random)

            filter := bson.D{{Key: "address", Value: random_address}}

            if err := user_collection.FindOne(context.TODO(), filter).Err(); err == mongo.ErrNoDocuments {
                break
            } else if err != nil {
                log.Println("Error checking address:", err.Error())
                responder.WriteError("Server error")
                return
            }
        }

        update := bson.D{{Key: "$addToSet", Value: bson.D{{Key: "addresses", Value: random_address}}}}

        result, err := user_collection.UpdateByID(context.Background(), user.Id, update)
        if err != nil || result.ModifiedCount != 1 {
            log.Println("Failed to update db", err.Error());
            responder.WriteError("Server error")
            return
        }

        responder.WriteData(random_address)
    })
}

func DeleteAddress(user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        remove_address_request, err := api_utils.DecodeJson[AddressRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse remove address request: ", err.Error())
            responder.WriteError("Malformed request")
            return
        }

        if remove_address_request.Address == user.MainEmail {
            log.Println("Tried to delete main address")
            responder.WriteError("You can't delete your main address")
            return
        }

        if !slices.Contains(user.Addresses, remove_address_request.Address) {
            log.Println("The address used doesn't exist on the user: ", remove_address_request.Address)
            responder.WriteError("This address doesn't exist")
            return
        }

        update := bson.D{{Key: "$pull", Value: bson.M{"addresses": remove_address_request.Address}}}
        _, err = user_collection.UpdateByID(context.TODO(), user.Id, update)
        if err != nil {
            log.Println("Failed to remove address from user: ", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Deleted address")
    })
}

func RotateAddress(user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        rotate_address_request, err := api_utils.DecodeJson[AddressRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse remove address request: ", err.Error())
            responder.WriteError("Malformed request")
            return
        }

        if !slices.Contains(user.Addresses, rotate_address_request.Address) {
            log.Println("The address used doesn't exist on the user: ", rotate_address_request.Address)
            responder.WriteError("This address doesn't exist")
            return
        }

        parts := strings.Split(rotate_address_request.Address, "@")
        if len(parts) != 2 {
            log.Println("The address format is not correct: ", rotate_address_request.Address)
            responder.WriteError("Bad address format")
            return
        }
        dot_separated := strings.Split(parts[0], ".")
        if len(parts) != 2 {
            log.Println("The address format is not correct: ", rotate_address_request.Address)
            responder.WriteError("Bad address format")
            return
        }
        address := dot_separated[0]

        var random_address string
        for {
            random, err := randomString(5)
            if err != nil {
                responder.WriteError("Server error")
            }
            random_address = fmt.Sprintf("%s.%s@secria.me", address, random)

            filter := bson.D{{Key: "address", Value: random_address}}

            if err := user_collection.FindOne(context.TODO(), filter).Err(); err == mongo.ErrNoDocuments {
                break
            } else if err != nil {
                log.Println("Error checking address:", err.Error())
                responder.WriteError("Server error")
                return
            }
        }

        // PIPELINE THIS!
        remove_update := bson.D{{Key: "$pull", Value: bson.M{"addresses": rotate_address_request.Address}}}
        _, err = user_collection.UpdateByID(context.TODO(), user.Id, remove_update)
        if err != nil {
            log.Println("Failed to remove address from user: ", err.Error())
            responder.WriteError("Server error")
            return
        }

        add_update := bson.D{{Key: "$addToSet", Value: bson.M{"addresses": random_address}}}
        _, err = user_collection.UpdateByID(context.TODO(), user.Id, add_update)
        if err != nil {
            log.Println("Failed to add address from user: ", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData(random_address)
    })
}

func DeleteUser(user_collection *mongo.Collection, metadata_collection *mongo.Collection, email_collection *mongo.Collection, cleanup_func func(int64)) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        filter := bson.D{{ Key: "_id", Value: user.Id}}
        result, err := user_collection.DeleteOne(context.Background(), filter)
        if err != nil || result.DeletedCount != 1 {
            log.Println("Failed to delete user: "+err.Error());
            responder.WriteError("Failed to delete user")
            return
        }

        responder.WriteData("Deleted user")
    })
}

type AddTagRequest struct {
    Name string `json:"name"`
    Color string `json:"color"`
}

func AddUserTag(user_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        var add_tag_request AddTagRequest 
        add_tag_request, err := api_utils.DecodeJson[AddTagRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse add tags request: ", err.Error())
            responder.WriteError("Invalid request body")
            return
        }
        if len(add_tag_request.Name) <= 3 {
            log.Println("Tag name is too short")
            responder.WriteError("Tag name is too short")
            return
        }

        if slices.ContainsFunc(user.Tags, func(t mongo_schemes.UserTag) bool { return t.Name == add_tag_request.Name}) {
            log.Println("A tag with this name already exists")
            responder.WriteError("A tag with this name already exists")
            return
        }

        tag := mongo_schemes.UserTag{
            Name: add_tag_request.Name,
            Color: add_tag_request.Color,
        }

        update := bson.M{
            "$addToSet": bson.M{
                "tags": tag,
            },
        }

        _, err = user_collection.UpdateByID(context.TODO(), user.Id, update)
        if err != nil {
            log.Println("Failed to add tag: "+err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        responder.WriteData("Added tag")
    })
}

type DeleteUserTagRequest struct {
    Name string `json:"name"`
}

func DeleteUserTag(user_collection *mongo.Collection, metadata_collection *mongo.Collection) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        responder := api_utils.NewJsonResponder[string](w)
        user := r.Context().Value("user").(mongo_schemes.User)

        del_tag_request, err := api_utils.DecodeJson[DeleteUserTagRequest](r.Body)
        if err != nil {
            log.Println("Failed to parse add tags request:", err.Error())
            responder.WriteError("Invalid request body")
            return
        }

        if !slices.ContainsFunc(user.Tags, func(t mongo_schemes.UserTag) bool { return t.Name == del_tag_request.Name }) {
            log.Println("This tag doesn't exist") 
            responder.WriteError("This tag doesn't exist")
            return
        }

        update := bson.M{
            "$pull": bson.M{
                "tags": bson.M{
                    "name": del_tag_request.Name,
                },
            },
        }

        _, err = user_collection.UpdateByID(context.TODO(), user.Id, update)
        if err != nil {
            log.Println("Failed to delete tag from user:", err.Error())
            responder.WriteError("Server error")
            return
        }

        metadata_filter := bson.D{{Key: "user_email", Value: user.MainEmail}}

        metadata_update := bson.M{
            "$pull": bson.M{
                "tags": del_tag_request.Name,
            },
        }

        _, err = metadata_collection.UpdateMany(context.TODO(), metadata_filter, metadata_update)
        if err != nil {
            log.Println("Failed to delete tag from metadata:", err.Error())
            responder.WriteError("Server error")
            return
        }

        responder.WriteData("Removed tag")
    })
}
