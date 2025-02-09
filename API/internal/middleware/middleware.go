package middleware

import (
	"context"
	"log"
	"net/http"
	"secria_api/internal/redis_handler"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
)

type Middleware func(http.Handler) http.Handler

func CreateStack(xs ...Middleware) Middleware {
    return func(next http.Handler) http.Handler {
        for i := len(xs)-1; i>= 0; i-- {
            x := xs[i];
            next = x(next);
        }
        return next;
    }
}

type wrappedWriter struct {
    http.ResponseWriter
    statusCode int
}

func (w *wrappedWriter) WriteHeader(statusCode int) {
    w.ResponseWriter.WriteHeader(statusCode)
    w.statusCode = statusCode
}

func Logging(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now().UTC()

        wrapped := wrappedWriter{
            ResponseWriter: w,
            statusCode: http.StatusOK,
        }
        next.ServeHTTP(&wrapped, r)
        log.Println(wrapped.statusCode, r.Method, r.URL.Path, time.Since(start))
    })
}

func AddJsonHeader(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type","application/json");
        next.ServeHTTP(w,r);
    })
}

func CookieAuth(redis_client *redis.Client, user_collection *mongo.Collection) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            session_cookie, err := r.Cookie("session")
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            cookie_object, err := redis_handler.GetCookieObject(redis_client, session_cookie.Value)
            if err != nil {
                http.Error(w, "Server Error", http.StatusInternalServerError)
                return
            }
            cookie_refresh := time.Unix(cookie_object.RefreshDate, 0)

            user, err := redis_handler.GetUserFromCookie(user_collection, cookie_object)
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            if !cookie_object.NoRefresh && cookie_refresh.Before(time.Now().UTC()) {
                new_cookie, err := redis_handler.RegenerateCookie(redis_client, session_cookie.Value, cookie_object)
                if err != nil {
                    http.Error(w, "Server Error", http.StatusInternalServerError)
                    return
                }
                http.SetCookie(w, &new_cookie)
            }

            ctx := context.WithValue(context.Background(), "user", user)
            r = r.WithContext(ctx)

            next.ServeHTTP(w, r)
        })
    }
}

func CorsMiddleware(allowed string) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Access-Control-Allow-Origin", allowed)
            w.Header().Set("Access-Control-Allow-Credentials", "true")
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

            if r.Method == http.MethodOptions {
                w.WriteHeader(http.StatusNoContent)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
