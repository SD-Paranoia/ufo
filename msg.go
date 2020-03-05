package ufo

type (
	/* Base64 encoded PKCS1v15 signature */
	Sig string

	/* SHA256 hash of  PEM encoded public key */
	FingerPrint string
)

/*
 * SignedFingerPrint is users public key fingerprint
 * and signature for the last provided UUID challenge
 */
type SignedFingerPrint struct {
	FingerPrint
	SignedChallenge Sig
}

/*
 * Group represents a group chat, identified by UUID
 */
type Group struct {
	UUID    string
	Members []FingerPrint
}

/*
 * Msg is a single message from or to a client
 */
type Msg struct {
	From    FingerPrint
	Content string
}

/*
 * JSON object expected for registration.
 * Public is the PEM encoded public key of the user.
 * Sig is the signature of that public key.
 */
type RegisterIn struct {
	Public string
	Sig    Sig
}

/*
 * JSON object for generating a challenge.
 */
type ChallengeIn struct {
	FingerPrint
}

/*
 * JSON object sent back on a challenge request.
 * UUID is the nonce for the user to sign to prove identity.
 */
type ChallengeOut struct {
	UUID string
}

/*
 * JSON object for reading messages.
 * GroupID is the UUID for a group.
 */
type ReadIn struct {
	SignedFingerPrint
	GroupID string
}

/*
 * JSON object returned on reads.
 */
type ReadOut struct {
	Msgs []Msg
}

/*
 * JSON object for write requests.
 * GroupID is the UUID of the group to be sent the message.
 * Content is the string of the message
 */
type WriteIn struct {
	SignedFingerPrint
	GroupID string
	Content string
}

/*
 * JSON object for list requests.
 */
type ListIn struct {
	SignedFingerPrint
}

/*
 * JSON object returned from list requests.
 */
type ListOut struct {
	GroupUUIDs []string
}

/*
 * JSON object for create group requests.
 * Group.UUID is not used.
 */
type GroupIn struct {
	Group
	SignedFingerPrint
}

/*
 * JSON object returned from create group requests
 */
type GroupOut struct {
	Error, UUID string
}
