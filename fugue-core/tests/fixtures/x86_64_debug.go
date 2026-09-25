package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
)

type record struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Tags   []string
	Digest string `json:"digest"`
}

func normalise(records []record) []record {
	normalised := make([]record, 0, len(records))
	for _, item := range records {
		item.Name = strings.TrimSpace(strings.ToLower(item.Name))
		sort.Strings(item.Tags)
		sum := sha256.Sum256([]byte(item.Name + strings.Join(item.Tags, ":")))
		item.Digest = hex.EncodeToString(sum[:])
		normalised = append(normalised, item)
	}
	sort.Slice(normalised, func(left, right int) bool {
		if normalised[left].Score == normalised[right].Score {
			return normalised[left].Name < normalised[right].Name
		}
		return normalised[left].Score > normalised[right].Score
	})
	return normalised
}

func recordsHandler(response http.ResponseWriter, request *http.Request) {
	var records []record
	if err := json.NewDecoder(request.Body).Decode(&records); err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(normalise(records)); err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
	}
}

func healthHandler(response http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(response, "ok")
}

func main() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/records", recordsHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
