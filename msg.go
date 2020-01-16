package ufo

/* ASCII Armor encoded values */
type (
	Sig         string
	FingerPrint string
)

type SignedFingerPrint struct {
	FingerPrint
	SignedChallenge Sig
}

type Group struct {
	UUID    string
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

type ChallengeIn struct {
	FingerPrint
}

type ChallengeOut struct {
	UUID string
}

type ReadIn struct {
	SignedFingerPrint
	GroupID string
}

type ReadOut struct {
	Msgs []Msg
}

type WriteIn struct {
	SignedFingerPrint
	GroupID string
	Content string
}

type ListIn struct {
	SignedFingerPrint
}

type ListOut struct {
	GroupUUIDs []string
}

type GroupIn struct {
	Group
	SignedFingerPrint
}

type GroupOut struct {
	Error, UUID string
}
