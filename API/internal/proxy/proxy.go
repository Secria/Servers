package proxy

import (
	"io"
	"net/http"
)

func ImageProxy(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    if url == "" {
        http.Error(w, "Missing parameter", http.StatusBadRequest)
        return
    }

    res, err := http.Get(url)
    if err != nil {
        http.Error(w, "Failed", http.StatusInternalServerError)
        return
    }
    defer res.Body.Close()

    w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
    io.Copy(w, res.Body)
}
