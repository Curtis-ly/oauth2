package token

import (
	"fmt"
	"time"

	"gopkg.in/oauth2.v2"
	"gopkg.in/oauth2.v2/models"

	"github.com/astaxie/beego/orm"
	_ "github.com/go-sql-driver/mysql"
)

// MysqlConfig Mysql Configuration
type MysqlConfig struct {
	// DB user
	DBUser string
	// DB password
	DBPassword string
	// DB Name(default oauth2)
	DBName string
	// DB Host
	DBHost string
	// DB Port
	DBPort string
	// Collection Name(default tokens)
	C string
}

func init() {
	orm.RegisterModel(new(models.Token))
}

// NewMysqlStore 创建Mysql的令牌存储
func NewMysqlStore(cfg *MysqlConfig) (store oauth2.TokenStore, err error) {
	if cfg.DBName == "" {
		cfg.DBName = "oauth2"
	}
	if cfg.C == "" {
		cfg.C = "tokens"
	}

	conn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&loc=Local", cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)

	orm.RegisterDriver("mysql", orm.DRMySQL)
	err = orm.RegisterDataBase("default", "mysql", conn)

	store = &MysqlStore{}

	return
}

// MysqlStore 令牌的mysql存储
type MysqlStore struct {
	cfg *MysqlConfig
}

// Create 存储令牌信息
func (ms *MysqlStore) Create(info oauth2.TokenInfo) (err error) {
	tm := info.(*models.Token)
	var expiredAt time.Time
	if refresh := tm.Refresh; refresh != "" {
		expiredAt = tm.RefreshCreateAt.Add(tm.RefreshExpiresIn)
		rinfo, _ := ms.GetByRefresh(refresh)
		if rinfo != nil {
			expiredAt = rinfo.GetRefreshCreateAt().Add(rinfo.GetRefreshExpiresIn())
		}
	}
	if expiredAt.IsZero() {
		expiredAt = tm.AccessCreateAt.Add(tm.AccessExpiresIn)
	}

	o := orm.NewOrm()
	_, err = o.Insert(tm)
	return
}

func (ms *MysqlStore) remove(token oauth2.TokenInfo) (err error) {
	o := orm.NewOrm()
	_, err = o.Delete(&token)
	return
}

// RemoveByAccess 移除令牌
func (ms *MysqlStore) RemoveByAccess(access string) error {
	o := orm.NewOrm()
	ti, err := ms.GetByAccess(access)
	if err != nil {
		return err
	}
	tm := ti.(*models.Token)
	_, err = o.Delete(tm)
	return err
}

// RemoveByRefresh 移除令牌
func (ms *MysqlStore) RemoveByRefresh(refresh string) error {
	o := orm.NewOrm()
	ti, err := ms.GetByRefresh(refresh)
	if err != nil {
		return err
	}
	tm := ti.(*models.Token)
	_, err = o.Delete(tm)
	return err
}

// GetByAccess 获取令牌数据
func (ms *MysqlStore) GetByAccess(access string) (ti oauth2.TokenInfo, err error) {
	var token models.Token
	qs := orm.NewOrm().QueryTable("token").Filter("access", access)
	err = qs.One(&token)
	return &token, err
}

// GetByRefresh 获取令牌数据
func (ms *MysqlStore) GetByRefresh(refresh string) (ti oauth2.TokenInfo, err error) {
	var token models.Token
	qs := orm.NewOrm().QueryTable("token").Filter("refresh", refresh)
	err = qs.One(&token)
	return &token, err
}
