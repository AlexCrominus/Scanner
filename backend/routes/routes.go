package routes

import (
	"scanner/controllers"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

	apiRoutes := router.Group("/")
	{
		apiRoutes.POST("/parse", controllers.ParseDomains)
		apiRoutes.GET("/ws-scan", controllers.WSScan)
	}

	return router
}
