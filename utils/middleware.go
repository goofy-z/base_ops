package utils

import (
	"bytes"
	"github.com/qq1141000259/public_tools/zlog"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"time"
)

// 中间键--错误处理+api日志
func HandleErrors() gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now()
		defer func() {
			// 记录接口耗时
			duration := time.Now().Sub(now).Seconds()
			if err := recover(); err != nil {
				var (
					errMsg string
					ok     bool
				)
				if errMsg, ok = err.(string); ok {
					c.JSON(http.StatusInternalServerError, gin.H{
						"code": 500,
						"msg":  "system error, " + errMsg,
					})
					zlog.Errorf("URL: %s duration: %fs msg: %s", c.Request.URL, duration, "system error, "+errMsg)
					return
				} else {
					c.JSON(http.StatusInternalServerError, gin.H{
						"code": 500,
						"msg":  "system error",
					})
					zlog.Errorf("URL: %s duration: %fs msg: %s %v", c.Request.URL, duration, "system error", err)
					return
				}
			}
		}()
		// 解析请求的json参数
		data, _ := ioutil.ReadAll(c.Request.Body)
		// 因为request.body是readcloser 需要重新填充Body
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(data))
		zlog.Infof("URL: %s req: %s", c.Request.URL, string(data))
		c.Next()
	}
}
