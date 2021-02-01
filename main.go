package main

import (
	"gin-jwt-example/controller"
	"github.com/gin-gonic/gin"
	"github.com/ken109/gin-jwt"
	"io/ioutil"
	"net/http"
)

func main() {
	pemBytes, err := ioutil.ReadFile("private.key")
	if err != nil {
		panic(err)
	}

	// セットアップ
	if err := jwt.SetUp(pemBytes, jwt.Option{}); err != nil {
		panic(err)
	}

	r := gin.New()

	r.POST("/login", controller.Login)

	auth := r.Group("/api")

	// 認証チェックしたいところでUseする
	auth.Use(jwt.Verify)

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
