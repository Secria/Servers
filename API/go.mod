module secria_api

go 1.24rc1

require (
	github.com/emersion/go-smtp v0.21.3
	github.com/google/uuid v1.6.0
	github.com/pquerna/otp v1.4.0
	github.com/redis/go-redis/v9 v9.7.0
	go.mongodb.org/mongo-driver v1.17.2
	golang.org/x/crypto v0.26.0
	shared v0.0.0
)

replace shared => ../shared

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
)
