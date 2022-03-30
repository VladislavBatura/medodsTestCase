// medods project main.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Token struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type TokenToMgo struct {
	Id           bson.ObjectId `bson:"_id"`
	UserGuid     string        `bson:"userGuid"`
	RefreshToken string        `bson:"refreshToken"`
	AccessUuid   string        `bson:"accessGuid"`
	RefreshUuid  string        `bson:"refreshGuid"`
	AtExpires    int64         `bson:"atExpires"`
	RtExpires    int64         `bson:"rtExpires"`
}

type TokenToSend struct {
	AccessToken  string
	RefreshToken string
}

type AccessDetails struct {
	AccessUuid string
	UserId     uint64
}

type TokenFromBody struct {
	refresh_token string
}

var connString string = "mongodb://127.0.0.1"

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/access", access)
	mux.HandleFunc("/refresh", refresh)
	log.Println("Server is ready")
	http.ListenAndServe(":4040", mux)
}

func access(w http.ResponseWriter, r *http.Request) {
	keys, ok := r.URL.Query()["guid"]

	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'guid' is missing")
		return
	}

	key := keys[0]
	token, err := createToken(key)

	if errCheck(err) {
		return
	}

	tokenDTO := createDTO(token, key)

	err = createAuth(key, tokenDTO)

	if errCheck(err) {
		return
	}

	dataToEncode := []byte(token.RefreshToken)
	encodedData := base64.StdEncoding.EncodeToString(dataToEncode)

	tokToSend := &TokenToSend{AccessToken: token.AccessToken, RefreshToken: encodedData}

	j, _ := json.Marshal(tokToSend)

	w.Write([]byte(j))
}

func refresh(w http.ResponseWriter, r *http.Request) {
	var refreshToken TokenFromBody
	err := json.NewDecoder(r.Body).Decode(&refreshToken)
	if errCheck(err) {
		return
	}

	decodedToken := decodeToken(refreshToken.refresh_token)

	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf")
	token, err := jwt.Parse(decodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	if errCheck(err) {
		return
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		_ = errCheck(err)
		return
	}

	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			_ = errCheck(err)
			return
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			_ = errCheck(err)
			return
		}
		//Delete the previous Refresh Token
		deleted, delErr := deleteAuth(refreshUuid)
		if delErr != nil || deleted == 0 { //if any goes wrong
			_ = errCheck(delErr)
			return
		}
		//Create new pairs of refresh and access tokens
		ts, createErr := createToken(string(userId))
		if createErr != nil {
			_ = errCheck(createErr)
			return
		}

		tokenToMgo := createDTO(ts, string(userId))
		//save the tokens metadata to redis
		saveErr := createAuth(tokenToMgo.UserGuid, tokenToMgo)
		if saveErr != nil {
			_ = errCheck(createErr)
			return
		}

		dataToEncode := []byte(ts.RefreshToken)
		encodedData := base64.StdEncoding.EncodeToString(dataToEncode)

		tokToSend := &TokenToSend{AccessToken: ts.AccessToken, RefreshToken: encodedData}

		j, _ := json.Marshal(tokToSend)

		w.Write([]byte(j))
	}
}

func createToken(user string) (*Token, error) {
	td := &Token{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["userGUID"] = user
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	at := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

	if errCheck(err) {
		return nil, err
	}

	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf")
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["userGUID"] = user
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))

	if errCheck(err) {
		return nil, err
	}

	return td, nil
}

func createDTO(t *Token, user string) *TokenToMgo {
	token := &TokenToMgo{
		Id:           bson.NewObjectId(),
		UserGuid:     user,
		RefreshToken: t.RefreshToken,
		AccessUuid:   t.AccessUuid,
		RefreshUuid:  t.RefreshUuid,
		AtExpires:    t.AtExpires,
		RtExpires:    t.RtExpires}

	hash, err := hashToken(token.RefreshToken)

	if errCheck(err) {
		log.Println("Can't hash this")
		return token
	}

	token.RefreshToken = hash

	return token
}

func createAuth(user string, t *TokenToMgo) error {

	session, err := mgo.Dial(connString)

	if errCheck(err) {
		return err
	}

	defer session.Close()

	mongoCollection := session.DB("local").C("tokens")

	err = mongoCollection.Insert(t)
	if errCheck(err) {
		return err
	}
	return nil
}

func hashToken(token string) (string, error) {
	cost, _ := bcrypt.Cost([]byte(token))
	bytes, err := bcrypt.GenerateFromPassword([]byte(token), cost)

	return string(bytes), err
}

func hashCompare(token, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
	return err == nil
}

func decodeToken(encodedToken string) string {
	decodedData, err := base64.StdEncoding.DecodeString(encodedToken)
	if errCheck(err) {
		return ""
	}

	stringData := string(decodedData)
	return stringData
}

func takeTokenFromDB(auth *AccessDetails) (uint64, error) {
	session, err := mgo.Dial(connString)

	if errCheck(err) {
		return 0, err
	}

	defer session.Close()

	mongoCollection := session.DB("local").C("tokens")

	query := bson.M{
		"accessGuid": auth.AccessUuid}

	var token TokenToMgo
	mongoCollection.Find(query).One(&token)
	userID, _ := strconv.ParseUint(token.UserGuid, 10, 64)
	return userID, nil
}

func deleteAuth(uuid string) (int, error) {
	session, err := mgo.Dial(connString)

	if errCheck(err) {
		return 0, err
	}

	defer session.Close()

	mongoCollection := session.DB("local").C("tokens")

	query := bson.M{
		"refreshGuid": uuid}

	_, err = mongoCollection.RemoveAll(query)
	if errCheck(err) {
		return 0, err
	}
	return 1, nil
}

func errCheck(err error) bool {
	if err != nil {
		log.Println(err.Error())
		return true
	}
	return false
}
