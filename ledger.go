package ufo

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

//ErrKeyExists is returned on registration when
//a someone has already registered with that key
var ErrKeyExists = errors.New("Key already exist")

//ErrAuthDenied is returned when a user has failed
//a verification challenge
var ErrAuthDenied = errors.New("Auth denied")

//ErrKeyNotExist is returned when a user tries to
//verify with a key that is not registered
var ErrKeyNotExist = errors.New("Key doesnt exist")

//ErrGroupExists is returned when a user tries to
//create a group with an existing UUID
var ErrGroupExists = errors.New("Group Exists")

//ErrBadUUID is returned when a user
//sends a malfromed UUID to the server.
var ErrBadUUID = errors.New("bad UUID")

var NoSuchUUID = errors.New("No such UUID")

type proof struct {
	SignedFingerPrint
	UUID string
}

func registerProc(rin chan RegisterIn, vin chan proof) (chan error, chan error) {
	keys := make(map[FingerPrint]*rsa.PublicKey)
	rout := make(chan error)
	vout := make(chan error)
	go func() {
		for {
			select {
			case msg := <-rin:
				pub, err := ParsePublicRSA(msg.Public)
				if err != nil {
					rout <- err
					continue
				}
				hashed := sha256.Sum256([]byte(msg.Public))
				fp := FingerPrint(hex.EncodeToString(hashed[:]))
				if _, ok := keys[fp]; ok {
					rout <- ErrKeyExists
					continue
				}
				keys[fp] = pub
				sig, err := base64.StdEncoding.DecodeString(string(msg.Sig))
				if err != nil {
					rout <- err
					continue
				}

				rout <- rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
			case msg := <-vin:
				pub, ok := keys[msg.SignedFingerPrint.FingerPrint]
				if !ok {
					vout <- ErrKeyNotExist
					continue
				}
				sig, err := base64.StdEncoding.DecodeString(string(msg.SignedChallenge))
				if err != nil {
					vout <- err
					continue
				}
				hashed := sha256.Sum256([]byte(msg.UUID))
				vout <- rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
			}
		}
	}()
	return rout, vout
}

type token struct {
	UUID string
	time.Time
}

func challengeProc(cin chan ChallengeIn, vin chan SignedFingerPrint) (chan ChallengeOut, chan error) {
	rec := make(map[FingerPrint]*token)
	cout := make(chan ChallengeOut)
	vout := make(chan error)
	go func() {
		for {
			select {
			case msg := <-cin:
				u, err := uuid.NewUUID()
				if err != nil {
					cout <- ChallengeOut{""}
					continue
				}
				us := u.String()
				tok := &token{us, time.Now()}
				rec[msg.FingerPrint] = tok
				cout <- ChallengeOut{us}
			case msg := <-vin:
				tok, ok := rec[msg.FingerPrint]
				if !ok {
					vout <- ErrAuthDenied
					continue
				}
				if time.Now().After(tok.Add(time.Hour)) {
					vout <- ErrAuthDenied
					continue
				}
				proofin <- proof{msg, tok.UUID}
				vout <- <-proofout
			}
		}
	}()
	return cout, vout
}

func msgProc(rin chan string, win chan WriteIn) (chan ReadOut, chan error) {
	msgs := make(map[uuid.UUID][]Msg)
	rout := make(chan ReadOut)
	wout := make(chan error)
	go func() {
		for {
			select {
			case msg := <-rin:
				uuid, err := uuid.Parse(msg)
				if err != nil {
					rout <- ReadOut{nil, err}
					continue
				}
				if out, ok := msgs[uuid]; ok {
					rout <- ReadOut{out, nil}
				} else {
					rout <- ReadOut{nil, NoSuchUUID}
				}
			case msg := <-win:
				uuid, err := uuid.Parse(msg.GroupID)
				if err != nil {
					wout <- fmt.Errorf("%w: %s", ErrBadUUID, uuid)
					continue
				}
				newmsg := Msg{
					msg.SignedFingerPrint.FingerPrint,
					msg.Content,
				}
				msgs[uuid] = append(msgs[uuid], newmsg)
				wout <- nil
			}
		}
	}()
	return rout, wout
}

func convoProc(makein chan Group, listin chan ListIn) (chan GroupOut, chan ListOut) {
	dir := make(map[uuid.UUID][]FingerPrint)
	bdir := make(map[FingerPrint][]uuid.UUID)
	makeout := make(chan GroupOut)
	listout := make(chan ListOut)
	go func() {
		for {
			select {
			case msg := <-makein:
				uuid := uuid.New()
				_, ok := dir[uuid]
				if ok {
					makeout <- GroupOut{Error: ErrGroupExists.Error()}
					continue
				}
				dir[uuid] = msg.Members
				for _, fp := range msg.Members {
					bdir[fp] = append(bdir[fp], uuid)
				}
				makeout <- GroupOut{UUID: uuid.String()}
			case msg := <-listin:
				us, ok := bdir[msg.SignedFingerPrint.FingerPrint]
				if !ok {
					listout <- ListOut{[]string{}}
					continue
				}
				lo := ListOut{}
				for _, u := range us {
					lo.GroupUUIDs = append(lo.GroupUUIDs, u.String())
				}
				listout <- lo
			}
		}
	}()
	return makeout, listout
}
