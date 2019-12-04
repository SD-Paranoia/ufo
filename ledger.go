package ufo

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var ErrKeyExists = errors.New("Key already exists")

type Ledger struct {
	*sync.RWMutex
	msgs map[uuid.UUID][]Msg
	keys map[FingerPrint]*openpgp.Entity
}

func NewLedger() *Ledger {
	return &Ledger{
		RWMutex: &sync.RWMutex{},
		msgs:    make(map[uuid.UUID][]Msg),
		keys:    make(map[FingerPrint]*openpgp.Entity),
	}
}

func (l *Ledger) AddMsg(uuid uuid.UUID, m Msg) {
	l.Lock()
	l.msgs[uuid] = append(l.msgs[uuid], m)
	l.Unlock()
}

func (l *Ledger) AddKey(public string) (*openpgp.Entity, error) {
	f := sha512.Sum512([]byte(public))
	fs := FingerPrint(hex.EncodeToString(f[:]))
	if l.FingerExists(fs) {
		return nil, ErrKeyExists
	}
	r := strings.NewReader(public)
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	pubEntity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		return nil, err
	}
	l.Lock()
	l.keys[fs] = pubEntity
	l.Unlock()
	return pubEntity, nil
}

func (l *Ledger) GroupExists(uuid uuid.UUID) bool {
	l.RLock()
	_, ok := l.msgs[uuid]
	l.RUnlock()
	return ok
}

func (l *Ledger) FingerExists(f FingerPrint) bool {
	l.RLock()
	_, ok := l.keys[f]
	l.RUnlock()
	return ok
}