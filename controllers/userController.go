package controllers

import (
	helper "Auth-Go-JWT-MongoDB/helpers"
	"Auth-Go-JWT-MongoDB/models"
	"context"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"net/http"
	"time"

	"Auth-Go-JWT-MongoDB/database"

	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

// Первый маршрут выдает пару Access, Refresh токенов
// для пользователя с идентификатором (GUID) указанным в параметре запроса
func GetTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Для проверки существования пользователя в базе
		//	   var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		//var foundUser models.User

		guid, ok := c.GetQuery("GUID")
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Url param GUID is missing"})
			return
		}

		// Проверяем, что такой пользователь есть в базе.
		/*  err := userCollection.FindOne(ctx, bson.M{"user_id": guid}).Decode(&foundUser)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no such user"})
			return
		} */

		// Генерируем токены
		accessToken, refreshToken, _ := helper.GenerateTokens(guid)

		// Возвращаем токены
		c.JSON(http.StatusOK, gin.H{
			"AccessToken":  accessToken,
			"RefreshToken": refreshToken})
	}
}

// Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов
func RefreshTokens() gin.HandlerFunc {
	return func(c *gin.Context) {

		var foundUser models.User
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		// Получаем refresh token
		refreshToken := c.Request.Header.Get("RefreshToken")
		if refreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}

		// Получаем access токен
		accessToken := c.Request.Header.Get("AccessToken")
		if accessToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}

		// Парсим refresh token , проверяем, что он валидный и не просроченный
		rclaims, expired := helper.ValidateToken(refreshToken)
		if rclaims == nil || expired {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Парсим access token, проверяем, что он валидный и просрочен
		aclaims, expired := helper.ValidateToken(accessToken)
		if aclaims == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		// Если access token не просрочен - выдаем в лог предупреждение
		if !expired {
			log.Print("Warning: attempt to refresh not expired access token. GUID: ", aclaims.Uid)
		}

		// Access, Refresh токены обоюдно связаны, Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.
		if aclaims.Id != rclaims.Id {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Проверяем, что refresh token совпадает с хранимым в базе
		err := userCollection.FindOne(ctx, bson.M{"user_id": aclaims.Uid}).Decode(&foundUser)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(*foundUser.Refresh_token), []byte(refreshToken))

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Генерируем и выдаем новую пару токенов
		newAT, newRT, _ := helper.GenerateTokens(aclaims.Uid)

		// Возвращаем токены
		c.JSON(http.StatusOK, gin.H{
			"AccessToken":  newAT,
			"RefreshToken": newRT})
	}
}
