package apis

import (
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"base_ops/service"
	"base_ops/utils"
	"net/http"
)

func Init() {

}

func Install(r *gin.Engine) *gin.Engine {
	// 性能分析工具
	pprof.Register(r)

	r.Use(utils.HandleErrors())

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"code": 404,
			"msg":  "找不到该路由",
		})
	})

	api := r.Group("/api/v1")
	// uwork重装
	api.POST("/reset", service.ReinstallOS)
	// uwork重装查询
	api.POST("/reset_status", service.ReinstallOSStatus)
	// 初始化
	api.POST("/init_server", service.InitServer)
	// 隔离
	api.POST("/isolate", service.IsoServer)
	// 取消隔离
	api.POST("/isolate_cancel", service.IsoServerCancel)
	// 获取磁盘信息
	api.POST("/disk_info", service.CheckoutDisk)
	// 修改密码
	api.POST("/change_passwd", service.ChangePasswd)
	return r
}
