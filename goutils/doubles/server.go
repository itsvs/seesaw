package doubles

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/itsvs/seesaw/goutils/doubles/db"
)

type server struct {
	db db.DB
}

func (s *server) listUsers(c *gin.Context) {
	users, err := s.db.ListUsers(c)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}
	c.JSON(http.StatusOK, users)
}

func (s *server) getUserById(c *gin.Context) {
	user, err := s.db.GetUserById(c, c.Param("id"))
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}
	c.JSON(http.StatusOK, user)
}

func (s *server) setupRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/list", s.listUsers)
	router.GET("/get/:id", s.getUserById)
	return router
}
