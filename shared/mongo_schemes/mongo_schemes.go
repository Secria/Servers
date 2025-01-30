package mongo_schemes

import "go.mongodb.org/mongo-driver/bson/primitive"

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

type UserPlansConfig struct {
    Plan string `bson:"plan"`
    Price float64 `bson:"price"`
    SpaceLimit int `bson:"space_limit"`
    DailyEmailLimit int `bson:"daily_limit"`
    SubaddressLimit int `bson:"subaddress_limit"`
    TagLimit int `bson:"tag_limit"`
}

type TrackedUsage struct {
    UsedSpace int `bson:"used_space"`
    SentEmails int `bson:"sent_email"`
}

type User struct {
    Id primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name string `bson:"name" json:"name"`
    Email string `bson:"email" json:"email"`
    Username string `bson:"username" json:"username"`
    Domain string `bson:"domain" json:"domain"`
    Subaddresses []string `bson:"subaddresses,omitempty" json:"subaddresses"`
    Password string `bson:"password" json:"-"`
    MainKey ECDH_MLKEM_KEY `bson:"main_key" json:"main_key"`
    Contacts []string `bson:"contacts,omitempty" json:"contacts"`
    Tags []UserTag `bson:"tags,omitempty" json:"tags"`
    PlansConfig UserPlansConfig `bson:"plan_config"`
    Usage TrackedUsage `bson:"usage"`
}

type Metadata struct {
    Id primitive.ObjectID `bson:"_id,omitempty"`
    Size int `bson:"size"`
    KeyUsed string `bson:"key_used"`
    UserEmail string `bson:"user_email"`
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
    ReferenceCount int `bson:"reference_count" json:"reference_count"`
}
