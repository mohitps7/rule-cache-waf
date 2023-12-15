package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func main() {
	cert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key")
	if err != nil {
		log.Fatalln(err)
	}

	s := &http.Server{
		Addr:    "localhost:9000",
		Handler: nil,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		},
	}

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		_, err := fmt.Fprint(res, "Response from Origin Server")
		if err != nil {
			log.Println(err)
			return
		}
	})

	log.Fatal(s.ListenAndServeTLS("localhost.crt", "localhost.key"))
}
