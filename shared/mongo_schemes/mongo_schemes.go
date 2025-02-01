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
    KeyId string `bson:"key_id" json:"key_id"`
    Encryption int `bson:"encryption" json:"encryption"`
}

const (
    Encryption_ECDH_MLKEM = 0
)

type ECDH_MLKEM_KEY struct {
    MLKEMPublicKey string `bson:"mlkem_public_key" json:"mlkem_public_key"`
    MLKEMPrivateKey string `bson:"mlkem_private_key_encrypted" json:"mlkem_private_key_encrypted"`
    DHPublicKey string `bson:"dh_public_key" json:"dh_public_key"`
    DHPrivateKey string `bson:"dh_private_key_encrypted" json:"dh_private_key_encrypted"`
    SentKey string `bson:"sent_key" json:"sent_key"`
    Key
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
    UsedSpace int `bson:"used_space" json:"used_space"`
    SentEmails int `bson:"sent_emails" json:"sent_emails"`
    ResetDate time.Time `bson:"reset_date"`
}

type EmailAddress struct {
    Address string `bson:"address"`
    UserId primitive.ObjectID `bson:"user_id"`
}

type User struct {
    Id primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name string `bson:"name" json:"name"`
    MainEmail string `bson:"email" json:"email"`
    // Username string `bson:"username" json:"username"`
    // Domain string `bson:"domain" json:"domain"`
    Addresses []string `bson:"addresses,omitempty" json:"addresses"`
    // Subaddresses []string `bson:"subaddresses,omitempty" json:"subaddresses"`
    Password string `bson:"password" json:"-"`
    MainKey ECDH_MLKEM_KEY `bson:"main_key" json:"main_key"`
    Contacts []string `bson:"contacts,omitempty" json:"contacts"`
    Tags []UserTag `bson:"tags,omitempty" json:"tags"`
    PlanConfig UserPlanConfig `bson:"plan_config" json:"plan_config"`
    Usage TrackedUsage `bson:"usage" json:"usage"`
}

type Metadata struct {
    Id primitive.ObjectID `bson:"_id,omitempty"`
    Size int `bson:"size"`
    KeyUsed string `bson:"key_used"`
    // UserEmail string `bson:"user_email"`
    UsedAddress string `bson:"used_address"`
    EmailID primitive.ObjectID `bson:"email_id"`
    MessageId string `bson:"message_id" json:"message_id"`
    Subject string `bson:"subject,omitempty"`
    From string `bson:"from"`
    Ciphertext string `bson:"ciphertext,omitempty"`
    EncryptedKey string `bson:"encrypted_key"`
    Private bool `bson:"private"`
    // Subaddress string `bson:"subaddress,omitempty"`
    Sent bool `bson:"sent,omitempty"`
    Read bool `bson:"read,omitempty"`
    Starred bool `bson:"starred,omitempty"`
    Archived bool `bson:"archived,omitempty"`
    BCC bool `bson:"bcc,omitempty"`
    Tags []string `bson:"tags,omitempty"`
    Deleted bool `bson:"deleted,omitempty"`
}

type Email struct {
    Id primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Encryption int `bson:"encryption" json:"encryption"`
    From string `bson:"from" json:"from"`
    Headers string `bson:"headers" json:"headers"`
    Body string `bson:"body" json:"body"`
    DHPublicKey string `bson:"dh_public,omitempty"`
}
