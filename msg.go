package ufo

type (
	//Sig is a base64 encoded PKCS1v15 signature
	Sig string

	//FingerPrint is a SHA256 hash of PEM encoded public key */
	FingerPrint string
)

//SignedFingerPrint is used to verify
//the authenticity of a user.
type SignedFingerPrint struct {
	FingerPrint         //Public key of user they claim to be
	SignedChallenge Sig //Signature of sha256 encoded UUID challenge
}

//Group represents a group chat, identified by UUID
type Group struct {
	UUID    string        //UUID of group
	Members []FingerPrint //Public keys of the members in that group
}

//Msg is a single message from or to a client
type Msg struct {
	From    FingerPrint //Sender's public key
	Content string      //Content of message
}

//RegisterIn is the JSON object
//for user registration.
type RegisterIn struct {
	Public string //Pem enoded public key
	Sig    Sig    //Signature of the contents of Public
}

//ChallengeIn is the JSON object
//for users to request a challenge
type ChallengeIn struct {
	FingerPrint //User's public key fingerprint
}

//ChallengeOut is the JSON object
//for challenge reuqest responses.
type ChallengeOut struct {
	UUID string //Plain text UUID that user must sign
}

//ReadIn is the JSON object
//for users to request their messages.
type ReadIn struct {
	SignedFingerPrint
	GroupID string
}

//ReadOut is the JSON object
//response for read requests.
type ReadOut struct {
	Msgs []Msg
	Err  error
}

//WriteIn is the JSON object
//for write requests.
type WriteIn struct {
	SignedFingerPrint
	GroupID string
	Content string
}

//ListIn is the JSON object
//for users to list what groups
//they are in.
type ListIn struct {
	SignedFingerPrint
}

//ListOut is the JSON object
//response for list requests.
type ListOut struct {
	GroupUUIDs []string
}

//GroupIn is the JSON object
//for conversation create
//requests
type GroupIn struct {
	Group
	SignedFingerPrint
}

//GroupOut is the JSON object
//response for conversation
//create requests.
type GroupOut struct {
	Error, UUID string
}
