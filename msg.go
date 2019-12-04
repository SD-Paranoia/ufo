package ufo

import "github.com/google/uuid"

/* ASCII Armor endoed values */
type (
	Sig         string
	FingerPrint string
)

type SignedFingerPrint struct {
	Sig
	FingerPrint
}

type Group struct {
	uuid.UUID
	Members []FingerPrint
}

type Msg struct {
	From    FingerPrint
	Content string
}

type RegisterIn struct {
	Public string
	Sig    Sig
}

type ReadIn struct {
	SignedFingerPrint
	GroupID uuid.UUID
}

type ReadOut struct {
	Msgs []Msg
}

type WriteIn struct {
	SignedFingerPrint
	Group   uuid.UUID
	Content string
}

type WriteOut struct {
	Err string
}

type ListIn struct {
	SignedFingerPrint
}

type ListOut struct {
	Groups []string
}
