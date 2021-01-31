package main

import (
	"gin-jwt/controller"
	"gin-jwt/util"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	if err := util.SetRsaPrivateKey("private.key"); err != nil {
		panic(err)
	}

	r := gin.New()

	r.POST("/login", controller.Login)

	auth := r.Group("/api")
	auth.Use(util.AuthCheck)
	auth.GET("/hello", func(c *gin.Context) {
		claims, ok := c.Get("claims")
		if ok {
			c.JSON(http.StatusOK, claims)
		} else {
			c.JSON(http.StatusOK, "Hello World")
		}
	})

	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}
