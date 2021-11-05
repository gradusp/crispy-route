package route

import (
	"context"
	_ "embed"
	"runtime"

	"encoding/json"
	"github.com/gradusp/crispy-route/pkg/route"
	"github.com/gradusp/go-platform/server"
	grpcRt "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	_ "github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

//GetSwaggerDocs get swagger spec docs
func GetSwaggerDocs() (*server.SwaggerSpec, error) {
	const api = "dummy/GetSwaggerDocs"
	ret := new(server.SwaggerSpec)
	err := json.Unmarshal(rawSwagger, ret)
	return ret, errors.Wrap(err, api)
}

//NewRouteService creates roure service
func NewRouteService(ctx context.Context) server.APIService {
	ret := &routeService{
		appCtx: ctx,
	}
	runtime.SetFinalizer(ret, func(o *routeService) {
		close(o.sema)
	})
	return ret
}

var (
	_ route.RouteServiceServer = (*routeService)(nil)
	_ server.APIService        = (*routeService)(nil)
	_ server.APIGatewayProxy   = (*routeService)(nil)
	//_ server.APIServiceOnStopEvent = (*routeService)(nil)

	//go:embed route.swagger.json
	rawSwagger []byte
)

type routeService struct {
	route.UnimplementedRouteServiceServer
	appCtx context.Context
	sema   chan struct{}
}

//Description impl server.APIService
func (srv *routeService) Description() grpc.ServiceDesc {
	return route.RouteService_ServiceDesc
}

//RegisterGRPC impl server.APIService
func (srv *routeService) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	route.RegisterRouteServiceServer(s, srv)
	return nil
}

//RegisterProxyGW impl server.APIGatewayProxy
func (srv *routeService) RegisterProxyGW(ctx context.Context, mux *grpcRt.ServeMux, c *grpc.ClientConn) error {
	return route.RegisterRouteServiceHandler(ctx, mux, c)
}

func (srv *routeService) enter(ctx context.Context) (leave func(), err error) {
	select {
	case <-srv.appCtx.Done():
		err = srv.appCtx.Err()
	case <-ctx.Done():
		err = ctx.Err()
	case srv.sema <- struct{}{}:
		leave = func() {
			<-srv.sema
		}
		return
	}
	err = status.FromContextError(err).Err()
	return
}
