package helpers

import (
	"Auth-Go-JWT-MongoDB/database"
	"context"
	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"time"
)

type SignedDetails struct {
	Uid string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

// Создает оба токена
func GenerateTokens(uid string) (signedToken string, signedRefreshToken string, e error) {

	// Храним один и тот же jti в обоих токенах, чтобы защититься от подмены одного из токенов
	jti := primitive.NewObjectID()

	claims := &SignedDetails{
		Uid: uid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Minute * time.Duration(5)).Unix(),
			Id:        jti.String(),
		},
	}

	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
			Id:        jti.String(),
		},
	}

	// Access токен тип JWT, алгоритм SHA512
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)
		return
	}

	// RefreshToken тип произвольный, формат передачи base64
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)
		return
	}

	// Сохраняем refresh token в базе
	err = SaveRToken(refreshToken, uid)
	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshToken, err

}

// Парсит, валидирует, проверяет срок токена
func ValidateToken(signedToken string) (claims *SignedDetails, expired bool) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err == nil {
		claims, ok := token.Claims.(*SignedDetails)
		if ok {
			return claims, false
		} else {
			return nil, false
		}
	}

	if err.(*jwt.ValidationError).Errors == jwt.ValidationErrorExpired {
		claims, ok := token.Claims.(*SignedDetails)
		if ok {
			return claims, true
		} else {
			return nil, true
		}
	}

	return
}

// Сохраняем Refresh токен в базе в виде bcrypt хеша
func SaveRToken(refreshToken string, guid string) error {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var updateObj primitive.D

	rtHashed, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 14)
	if err != nil {
		return err
	}
	updateObj = append(updateObj, bson.E{"refresh_token", string(rtHashed)})
	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{"updated_at", Updated_at})

	upsert := true
	filter := bson.M{"user_id": guid}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err = userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{"$set", updateObj},
		},
		&opt,
	)
	defer cancel()

	return err
}
