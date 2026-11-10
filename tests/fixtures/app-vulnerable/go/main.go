package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var db *sql.DB

func auth(c *gin.Context) {
	token, _ := jwt.Parse(c.GetHeader("Authorization"), func(t *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if token == nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
	}
	c.Next()
}

func main() {
	r := gin.Default()
	r.GET("/users/:id", func(c *gin.Context) {
		row := db.QueryRow(fmt.Sprintf("SELECT email FROM users WHERE id = %s", c.Param("id")))
		var email string
		if err := row.Scan(&email); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"email": email})
	})
	r.POST("/convert", auth, func(c *gin.Context) {
		out, _ := exec.Command("sh", "-c", "convert "+c.PostForm("file")+" out.png").Output()
		c.String(200, string(out))
	})
	r.GET("/files", func(c *gin.Context) {
		c.File("uploads/" + c.Query("name"))
	})
	r.GET("/fetch", func(c *gin.Context) {
		resp, _ := http.Get(c.Query("url"))
		c.DataFromReader(200, resp.ContentLength, "text/plain", resp.Body, nil)
	})
	_ = md5.Sum([]byte(fmt.Sprint(rand.Int())))
	http.ListenAndServe(":8080", r)
}
