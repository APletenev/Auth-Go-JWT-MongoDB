package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID            primitive.ObjectID `bson:"_id"`
	Refresh_token *string            `json:"refresh_token"`
	Updated_at    time.Time          `json:"updated_at"` // Для удобства тестирования
	User_id       string             `json:"user_id"`
}
