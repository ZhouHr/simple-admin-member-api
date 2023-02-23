// Code generated by goctl. DO NOT EDIT.
package handler

import (
	"net/http"

	base "github.com/suyuan32/simple-admin-member-api/internal/handler/base"
	member "github.com/suyuan32/simple-admin-member-api/internal/handler/member"
	memberrank "github.com/suyuan32/simple-admin-member-api/internal/handler/memberrank"
	"github.com/suyuan32/simple-admin-member-api/internal/svc"

	"github.com/zeromicro/go-zero/rest"
)

func RegisterHandlers(server *rest.Server, serverCtx *svc.ServiceContext) {
	server.AddRoutes(
		[]rest.Route{
			{
				Method:  http.MethodGet,
				Path:    "/init/database",
				Handler: base.InitDatabaseHandler(serverCtx),
			},
		},
	)

	server.AddRoutes(
		rest.WithMiddlewares(
			[]rest.Middleware{serverCtx.Authority},
			[]rest.Route{
				{
					Method:  http.MethodPost,
					Path:    "/member/create",
					Handler: member.CreateMemberHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member/update",
					Handler: member.UpdateMemberHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member/delete",
					Handler: member.DeleteMemberHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member/list",
					Handler: member.GetMemberListHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member",
					Handler: member.GetMemberByIdHandler(serverCtx),
				},
			}...,
		),
		rest.WithJwt(serverCtx.Config.Auth.AccessSecret),
	)

	server.AddRoutes(
		rest.WithMiddlewares(
			[]rest.Middleware{serverCtx.Authority},
			[]rest.Route{
				{
					Method:  http.MethodPost,
					Path:    "/member_rank/create",
					Handler: memberrank.CreateMemberRankHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member_rank/update",
					Handler: memberrank.UpdateMemberRankHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member_rank/delete",
					Handler: memberrank.DeleteMemberRankHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member_rank/list",
					Handler: memberrank.GetMemberRankListHandler(serverCtx),
				},
				{
					Method:  http.MethodPost,
					Path:    "/member_rank",
					Handler: memberrank.GetMemberRankByIdHandler(serverCtx),
				},
			}...,
		),
		rest.WithJwt(serverCtx.Config.Auth.AccessSecret),
	)
}
