package publicmember

import (
	"net/http"

	"github.com/zeromicro/go-zero/rest/httpx"

	"github.com/suyuan32/simple-admin-member-api/internal/logic/publicmember"
	"github.com/suyuan32/simple-admin-member-api/internal/svc"
	"github.com/suyuan32/simple-admin-member-api/internal/types"
)

// swagger:route post /member/login_by_email publicmember LoginByEmail
//
// Log in by email | 邮箱登录
//
// Log in by email | 邮箱登录
//
// Parameters:
//  + name: body
//    require: true
//    in: body
//    type: LoginByEmailReq
//
// Responses:
//  200: LoginResp

func LoginByEmailHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.LoginByEmailReq
		if err := httpx.Parse(r, &req, true); err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
			return
		}

		l := publicmember.NewLoginByEmailLogic(r.Context(), svcCtx)
		resp, err := l.LoginByEmail(&req)
		if err != nil {
			err = svcCtx.Trans.TransError(r.Context(), err)
			httpx.ErrorCtx(r.Context(), w, err)
		} else {
			httpx.OkJsonCtx(r.Context(), w, resp)
		}
	}
}
