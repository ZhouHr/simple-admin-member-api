package oauthprovider

import (
	"context"
	"github.com/suyuan32/simple-admin-member-api/internal/logic/publicmember"
	"github.com/suyuan32/simple-admin-member-rpc/types/mms"
	"net/http"
	"strings"
	"time"

	"github.com/suyuan32/simple-admin-common/utils/jwt"
	"github.com/suyuan32/simple-admin-common/utils/pointy"

	"github.com/suyuan32/simple-admin-member-api/internal/svc"
	"github.com/suyuan32/simple-admin-member-api/internal/types"

	"github.com/zeromicro/go-zero/core/logx"
)

type OauthCallbackLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
	r      *http.Request
}

func NewOauthCallbackLogic(r *http.Request, svcCtx *svc.ServiceContext) *OauthCallbackLogic {
	return &OauthCallbackLogic{
		Logger: logx.WithContext(r.Context()),
		ctx:    r.Context(),
		svcCtx: svcCtx,
		r:      r,
	}
}

func (l *OauthCallbackLogic) OauthCallback() (resp *types.CallbackResp, err error) {
	result, err := l.svcCtx.MmsRpc.OauthCallback(l.ctx, &mms.CallbackReq{
		State: l.r.FormValue("state"),
		Code:  l.r.FormValue("code"),
	})
	if err != nil {
		return nil, err
	}

	token, err := jwt.NewJwtToken(l.svcCtx.Config.Auth.AccessSecret, time.Now().Unix(),
		l.svcCtx.Config.Auth.AccessExpire, jwt.WithOption("userId", result.Id))

	// add token into database
	expiredAt := time.Now().Add(time.Second * 259200).Unix()
	_, err = l.svcCtx.MmsRpc.CreateToken(l.ctx, &mms.TokenInfo{
		Uuid:      result.Id,
		Token:     pointy.GetPointer(token),
		Source:    pointy.GetPointer(strings.Split(l.r.FormValue("state"), "-")[1]),
		Status:    pointy.GetPointer(uint32(1)),
		ExpiredAt: pointy.GetPointer(expiredAt),
	})

	if err != nil {
		return nil, err
	}

	return &types.CallbackResp{
		UserId:   *result.Id,
		Token:    token,
		Expire:   uint64(time.Now().Add(time.Second * 259200).Unix()),
		Avatar:   *result.Avatar,
		RankId:   *result.RankId,
		RankName: publicmember.MemberRankData[*result.RankId],
		Nickname: *result.Nickname,
	}, nil
}
