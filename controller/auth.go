package controller

import (
	"gin-jwt-example/model"
	"github.com/gin-gonic/gin"
	"github.com/ken109/gin-jwt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func Login(c *gin.Context) {
	password, _ := bcrypt.GenerateFromPassword([]byte("password"), 10)
	user := model.User{
		ID:       "user1",
		Password: string(password),
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("password")); err != nil {
		c.JSON(http.StatusForbidden, map[string]string{"error": "login failed"})
		return
	} else {
		// Tokenを吐き出す
		token, err := jwt.GetToken(map[string]interface{}{
			"id":    user.ID,
			"admin": true,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed"})
			return
		}
		c.JSON(http.StatusOK, map[string]interface{}{"token": string(token)})
	}
}
