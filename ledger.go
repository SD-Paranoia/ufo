package ufo

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var ErrKeyExists = errors.New("Key already exist")
var ErrAuthDenied = errors.New("Auth denied")
var ErrKeyNotExist = errors.New("Key doesnt exist")
var ErrGroupExists = errors.New("Group Exists")
var ErrBadUUID = errors.New("bad UUID")

func MakeFingerPrint(pub string) FingerPrint {
	f := sha512.Sum512([]byte(pub))
	return FingerPrint(hex.EncodeToString(f[:]))
}

func parsePublic(public string) (FingerPrint, *openpgp.Entity, error) {
	var fp FingerPrint
	r := strings.NewReader(public)
	block, err := armor.Decode(r)
	if err != nil {
		return fp, nil, err
	}
	pubEntity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		return fp, nil, err
	}
	return MakeFingerPrint(public), pubEntity, nil
}

type Proof struct {
	SignedFingerPrint
	UUID string
}

func registerProc(rin chan RegisterIn, vin chan Proof) (chan error, chan error) {
	keys := make(map[FingerPrint]*openpgp.Entity)
	rout := make(chan error)
	vout := make(chan error)
	go func() {
		for {
			select {
			case msg := <-rin:
				fp, pub, err := parsePublic(msg.Public)
				if err != nil {
					rout <- err
					continue
				}
				if _, ok := keys[fp]; ok {
					rout <- ErrKeyExists
					continue
				}
				keys[fp] = pub
				_, err = openpgp.CheckArmoredDetachedSignature(openpgp.EntityList{pub}, strings.NewReader(msg.Public), strings.NewReader(string(msg.Sig)))
				rout <- err
			case msg := <-vin:
				pub, ok := keys[msg.SignedFingerPrint.FingerPrint]
				if !ok {
					vout <- ErrKeyNotExist
					continue
				}
				_, err := openpgp.CheckArmoredDetachedSignature(openpgp.EntityList{pub}, strings.NewReader(msg.UUID), strings.NewReader(string(msg.SignedFingerPrint.SignedChallenge)))
				vout <- err
			}
		}
	}()
	return rout, vout
}

type Token struct {
	UUID string
	time.Time
}

func challengeProc(cin chan ChallengeIn, vin chan SignedFingerPrint) (chan ChallengeOut, chan error) {
	rec := make(map[FingerPrint]*Token)
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
				tok := &Token{us, time.Now()}
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
				proofin <- Proof{msg, tok.UUID}
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
					rout <- ReadOut{nil}
					continue
				}
				rout <- ReadOut{msgs[uuid]}
			case msg := <-win:
				uuid, err := uuid.Parse(msg.GroupID)
				if err != nil {
					wout <- ErrBadUUID
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
