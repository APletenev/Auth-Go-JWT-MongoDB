package main

import (
	controller "Auth-Go-JWT-MongoDB/controllers"
	"github.com/gin-gonic/gin"
	"os"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	router.Use(gin.Logger())

	// Первый маршрут выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса
	router.GET("/tokens", controller.GetTokens())

	// Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов
	router.POST("/refresh", controller.RefreshTokens())

	router.Run(":" + port)
}
