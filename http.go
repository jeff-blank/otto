package main

import (
	"net/http"
)

func statusCheck(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(200)
	rw.Write([]byte("OK"))
}

func statusInfo(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(200)
	info := "Interesting stuff goes here"
	rw.Write([]byte(info))
}
