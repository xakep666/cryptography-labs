package main

import (
	"crypto/sha1"
	"cryptolabs"
	"cryptolabs/lab1/task3"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"
)

var key []byte
var addr string
var delay time.Duration

func init() {
	rand.Seed(time.Now().Unix())
	key = task3.RandByteArray(rand.Intn(100))
	flag.StringVar(&addr, "addr", "127.0.0.1:8000", "address to listen requests")
	flag.DurationVar(&delay, "delay", 50*time.Millisecond, "delay between bytes comparsion in arrays")
	flag.Parse()
}

func insecureCompare(arr1, arr2 [sha1.Size]byte) bool {
	for i := 0; i < sha1.Size; i++ {
		if arr1[i] != arr2[i] {
			return false
		}
		time.Sleep(delay)
	}
	return true
}

func StartServer(address string, comparsionDelay time.Duration) error {
	http.HandleFunc("/test", testHmac)
	http.HandleFunc("/calc", calcHmac)
	return http.ListenAndServe(address, nil)
}

func calcHmac(w http.ResponseWriter, r *http.Request) {
	file, ok := r.URL.Query()["file"]
	if !ok {
		http.Error(w, "missing \"file\" parameter", 422)
		return
	}
	calculatedHmac := cryptolabs.HmacSHA1(key, []byte(file[0]))
	fmt.Fprintf(w, "% X", calculatedHmac)
}

func testHmac(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto)
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
	calculatedHmac := cryptolabs.HmacSHA1(key, []byte(file[0]))
	if insecureCompare(calculatedHmac, hmac) {
		http.Error(w, "hmac ok", 200)
	} else {
		http.Error(w, "hmac invalid", 500)
	}
}

func main() {
	log.Printf("Listening on %s, delay %v", addr, delay)
	if err := StartServer(addr, delay); err != nil {
		panic(err)
	}
}
