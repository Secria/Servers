package api_utils

import (
	"encoding/json"
	"net/http"
	"strings"

	"go.mongodb.org/mongo-driver/bson/primitive"
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
