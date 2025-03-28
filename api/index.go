package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "<h1>Hello from Go!</h1>")
}

func main() {
  http.HandleFunc("/", handler)
  fmt.Println("Server running on http://localhost:8080")
  http.ListenAndServe(":8080", nil)
}
