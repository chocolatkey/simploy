package simploy

import (
	"io/ioutil"
	"net/http"
)

const MaxBodySize = int64(10 << 20)

func safelyReadBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return ioutil.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodySize))
}
