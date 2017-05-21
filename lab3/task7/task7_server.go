package task7

import (
	"crypto/sha1"
	"cryptolabs"
	"cryptolabs/lab1/task3"
	"encoding/hex"
	"math/rand"
	"net/http"
	"time"
	//"log"
)

const Delay = time.Millisecond * 50

var Key []byte
var srv http.Server

func init() {
	rand.Seed(time.Now().Unix())
	Key = task3.RandByteArray(rand.Intn(100))
}

type myHandler struct{}

func (m myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//log.Println(r.Method, r.RequestURI, r.Proto)
	if r.URL.Path == "/test" {
		m.testHmac(w, r)
	} else {
		http.Error(w, "invalid path", 404)
	}
}

func insecureCompare(arr1, arr2 [sha1.Size]byte) bool {
	for i := 0; i < sha1.Size; i++ {
		if arr1[i] != arr2[i] {
			return false
		}
		time.Sleep(Delay)
	}
	return true
}

func StartServer(address string) (err error) {
	srv.Addr = address
	srv.Handler = myHandler{}
	go func() {
		err = srv.ListenAndServe()
	}()
	time.Sleep(time.Millisecond)
	return err
}

func (myHandler) testHmac(w http.ResponseWriter, r *http.Request) {
	file, ok := r.URL.Query()["file"]
	if !ok {
		http.Error(w, "missing \"file\" parameter", 422)
		return
	}
	hmacRaw, ok := r.URL.Query()["signature"]
	if !ok {
		http.Error(w, "missing \"signature\" parameter", 422)
		return
	}
	hmacArr, err := hex.DecodeString(hmacRaw[0])
	if err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	var hmac [sha1.Size]byte
	if len(hmacArr) != sha1.Size {
		http.Error(w, "incorrect hmac size", 422)
		return
	}
	copy(hmac[:], hmacArr)
	calculatedHmac := cryptolabs.HmacSHA1(Key, []byte(file[0]))
	if insecureCompare(calculatedHmac, hmac) {
		http.Error(w, "hmac ok", 200)
	} else {
		http.Error(w, "hmac invalid", 500)
	}
}

func StopServer() {
	srv.Close()
}
