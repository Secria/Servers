package api_utils

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"shared/mongo_schemes"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type ContactResponse struct {
    Name string `json:"name"`
    Email string `json:"email"`
    MLKEMPublicKey string `json:"mlkem_public"`
    DHPublicKey string `json:"dh_public"`
}

type ResponseEmail struct {
    Id primitive.ObjectID `json:"id"`
    Encryption int `json:"encryption"`
    KeyUsed string `json:"used_key"`
    From string `json:"from"`
    MessageId string `json:"message_id"`
    Headers string `json:"headers"`
    Body string `json:"body"`
    CipherText string `json:"ciphertext,omitempty"`
    EncryptedKey string `json:"encrypted_key"`
    DHPublicKey string `json:"dh_public,omitempty"`
    Private bool `json:"private"`
    Sent bool `json:"sent,omitempty"`
    Read bool `json:"read,omitempty"`
    Starred bool `json:"starred,omitempty"`
    Tags []string `json:"tags,omitempty"`
}

type LoginResponse struct {
    User mongo_schemes.User `json:"user"`
    Contacts []ContactResponse `json:"contacts"`
}

type APIResponseData[T any] struct {
    Success bool `json:"success"`
    Data T `json:"data"`
}

type APIErrorResponse APIResponseData[string]

type APIResponseCount[T any] struct {
    APIResponseData[T]
    Count int `json:"count"`
}

type JsonResponder[T any] struct {
    encoder *json.Encoder
}

func NewJsonResponder[T any](w http.ResponseWriter) JsonResponder[T] {
    return JsonResponder[T]{
        encoder: json.NewEncoder(w),
    }
}

func (r *JsonResponder[T]) WriteError(err... string) error {
    return r.encoder.Encode(APIErrorResponse{
        Success: false,
        Data: strings.Join(err, " "),
    })
}

func (r *JsonResponder[T]) WriteData(data T) error {
    return r.encoder.Encode(APIResponseData[T]{
        Success: true,
        Data: data,
    })
}

func (r *JsonResponder[T]) WriteCountData(data T, count int) error {
    return r.encoder.Encode(APIResponseCount[T]{
        APIResponseData: APIResponseData[T]{
            Success: true,
            Data: data,
        },
        Count: count,
    })
}

func DecodeJson[T any](encoded io.Reader) (T, error) {
    var data T
    err := json.NewDecoder(encoded).Decode(&data)
    return data, err
}

func UnmarshalJson[T any](encoded []byte) (T, error) {
    var data T
    err := json.Unmarshal(encoded, &data)
    return data, err
}

func RetrieveContacts(ctx context.Context, user_collection *mongo.Collection, emails []string) ([]ContactResponse, error) {
    filter := bson.M{"email": bson.M{"$in": emails}}
    cur, err := user_collection.Find(ctx, filter)
    if err != nil {
        return nil, err
    }
    defer cur.Close(ctx)

    var users []mongo_schemes.User
    if err = cur.All(ctx, &users); err != nil {
        return nil, err
    }

    var contacts []ContactResponse = make([]ContactResponse, 0, len(emails)) 
    for _, u := range users {
        contacts = append(contacts, ContactResponse{Name: u.Name, Email: u.MainEmail, MLKEMPublicKey: u.MainKey.MLKEMPublicKey, DHPublicKey: u.MainKey.DHPublicKey})
    }

    return contacts, nil
}

