package ufo

import (
	"net/http"
	"strings"
)

//Event is a log event
type Event struct {
	Description string
	Error       error
}

func (e *Event) String() string {
	switch e.Error {
	case nil:
		return e.Description
	default:
		return e.Description + " : " + e.Error.Error()
	}
}

func log2page(ev []Event) string {
	b := &strings.Builder{}
	for i := range ev {
		b.WriteString((&ev[i]).String() + "\n")
	}
	return b.String()
}

var eventOut = make(chan string)

func logger(in chan Event) {
	go func() {
		evLog := []Event{}
		for {
			select {
			case e := <-in:
				evLog = append(evLog, e)
			case eventOut <- log2page(evLog):
			}
		}
	}()
}

//LogHandler is the debug page for viewing errors
func LogHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(<-eventOut))
}
