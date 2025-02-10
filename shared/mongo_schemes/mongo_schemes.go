package mongo_schemes

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserTag struct {
    Name string `bson:"name" json:"name"`
    Color string `bson:"color" json:"color"`
}

type Key struct {
    KeyId []byte `bson:"key_id" json:"key_id"`
    Encryption int `bson:"encryption" json:"encryption"`
}

const (
    Encryption_ECDH_MLKEM = 0
)

type ECDH_MLKEM_KEY struct {
    MLKEMPublicKey []byte `bson:"mlkem_public_key" json:"mlkem_public_key"`
    MLKEMPrivateKey []byte `bson:"mlkem_private_key_encrypted" json:"mlkem_private_key_encrypted"`
    DHPublicKey []byte `bson:"dh_public_key" json:"dh_public_key"`
    DHPrivateKey []byte `bson:"dh_private_key_encrypted" json:"dh_private_key_encrypted"`
    SentKey []byte `bson:"sent_key" json:"sent_key"`
    Key
}

type EncryptionMetadata struct {
    From primitive.ObjectID `bson:"from"`
    To primitive.ObjectID `bson:"to"`
}

type UserPlanConfig struct {
    Plan string `bson:"plan" json:"plan"`
    Price float64 `bson:"price" json:"price"`
    SpaceLimit int `bson:"space_limit" json:"space_limit"`
    DailyEmailLimit int `bson:"daily_limit" json:"daily_limit"`
    AddressLimit int `bson:"address_limit" json:"address_limit"`
    TagLimit int `bson:"tag_limit" json:"tag_limit"`
}

type TrackedUsage struct {
    Id primitive.ObjectID `bson:"_id,omitempty"`
    Email string `bson:"email" json:"-"`
    UsedSpace int `bson:"used_space" json:"used_space"`
    SentEmails int `bson:"sent_emails" json:"sent_emails"`
    ResetDate time.Time `bson:"reset_date" json:"-"`
}

type User struct {
    Id primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name string `bson:"name" json:"name"`
    MainEmail string `bson:"email" json:"email"`
    Addresses []string `bson:"addresses" json:"addresses"`
    Password string `bson:"password" json:"-"`
    MainKey ECDH_MLKEM_KEY `bson:"main_key" json:"main_key"`
    Contacts []string `bson:"contacts,omitempty" json:"contacts"`
    Tags []UserTag `bson:"tags,omitempty" json:"tags"`
    PlanConfig UserPlanConfig `bson:"plan_config" json:"plan_config"`
    Usage primitive.ObjectID `bson:"usage" json:"usage"`
    TOTPActive bool `bson:"totp_active,omitempty" json:"totp_active,omitempty"`
    TOTPSecret string `bson:"totp_secret,omitempty" json:"-"`
}

type Metadata struct {
    Id primitive.ObjectID `bson:"_id,omitempty"`
    Size int64 `bson:"size"`
    KeyUsed []byte `bson:"key_used"`
    EncryptedKey []byte `bson:"encrypted_key"`
    Ciphertext[]byte `bson:"mlkem_cipher"`
    UsedAddress string `bson:"used_address"`
    EmailID primitive.ObjectID `bson:"email_id"`
    MessageId string `bson:"message_id" json:"message_id"`
    Subject string `bson:"subject,omitempty"`
    From string `bson:"from"`
    Private bool `bson:"private"`
    Sent bool `bson:"sent,omitempty"`
    Read bool `bson:"read,omitempty"`
    Starred bool `bson:"starred,omitempty"`
    Archived bool `bson:"archived,omitempty"`
    Tags []string `bson:"tags,omitempty"`
    Deleted bool `bson:"deleted,omitempty"`
    Attachment bool `bson:"attachment,omitempty"`
}

type Attachment struct {
    Filename string `bson:"filename" json:"filename"`
    ContentType string `bson:"content_type" json:"content_type"`
    Size int64 `bson:"size" json:"size"`
    Reference string `bson:"reference" json:"reference"`
}

type Email struct {
    Id primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Encryption int `bson:"encryption" json:"encryption"`
    DHPublicKey []byte `bson:"dh_public"`
    From string `bson:"from" json:"from"`
    FromId primitive.ObjectID `bson:"from_id"`
    Headers string `bson:"headers" json:"headers"`
    Body []byte `bson:"body" json:"body"`
    Attachments []Attachment `bson:"attachments,omitempty"`
}
