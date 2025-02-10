package attachment

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"

	"github.com/minio/minio-go/v7"
)

func DownloadAttachment(client *minio.Client, bucket string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ref := r.URL.Query().Get("ref")
        if ref == "" {
            http.Error(w, "Bad parameters", http.StatusBadRequest)
            return
        }

        res, err := client.GetObject(context.TODO(), bucket, ref, minio.GetObjectOptions{})
        if err != nil {
            http.Error(w, "Server error", http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/octet-stream")
        b, err := io.ReadAll(res)
        if err != nil {
            return
        }
        log.Println("Bytes", b)
        io.Copy(w, bytes.NewBuffer(b))
    }
}
