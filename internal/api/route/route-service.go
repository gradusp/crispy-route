package route

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	intNet "github.com/gradusp/crispy-route/internal/pkg/net"
	"github.com/gradusp/crispy-route/pkg/route"
	"github.com/gradusp/go-platform/logger"
	"github.com/gradusp/go-platform/pkg/slice"
	"github.com/gradusp/go-platform/server"
	grpcRt "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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
		sema:   make(chan struct{}, 1),
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

	//go:embed route.swagger.json
	rawSwagger []byte
)

const (
	ip4parts = `(?:\d+\.){3}\d+`
	tunPart  = `dev\s+tun(\d+)`
	ipAndTun = `(?mi)(?:\s|^)(` + ip4parts + `)\s+` + tunPart + `(?:\s|$)`

	mask32 = "/32"
)

var (
	reIPAndTun = regexp.MustCompile(ipAndTun)
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

//AddRoute impl service
func (srv *routeService) AddRoute(ctx context.Context, req *route.AddRouteRequest) (resp *emptypb.Empty, err error) {
	hcDestIP := req.GetHcDestIP()
	hcTunDestIP := req.GetHcTunDestIP()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("hcDestIP", hcDestIP),
		attribute.String("hcTunDestIP", hcTunDestIP),
	)

	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()
	resp = new(emptypb.Empty)
	var (
		hcTunDestNetIP net.IP
		hcDestNetIP    net.IP
		hcDestNetIPNet *net.IPNet
	)
	if hcTunDestNetIP, _, err = net.ParseCIDR(hcTunDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "'hcTunDestIP': %v",
			errors.Wrap(err, "net.ParseCIDR"),
		)
		return
	}
	span.SetAttributes(attribute.Stringer("hcTunDestNetIP", hcTunDestNetIP))

	if hcDestNetIP, hcDestNetIPNet, err = net.ParseCIDR(hcDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "'hcDestIP': %v",
			errors.Wrap(err, "net.ParseCIDR"),
		)
		return
	}
	span.SetAttributes(
		attribute.Stringer("hcDestNetIP", hcDestNetIP),
		attribute.Stringer("hcDestNetIPNet", hcDestNetIPNet),
	)

	table := int(intNet.IPType(hcTunDestNetIP).Int())
	tunnelName := fmt.Sprintf("tun%v", table)

	span.SetAttributes(attribute.String("tunnelName", tunnelName))
	srv.addSpanDbgEvent(ctx, span, "checkRouteExist", trace.WithAttributes(
		attribute.Stringer("hcDestNetIP", hcDestNetIP),
		attribute.String("tunnelName", tunnelName),
	))
	var isRouteExist bool
	if isRouteExist, err = srv.checkRouteExist(ctx, hcDestNetIP.String(), tunnelName); err != nil {
		err = errors.Wrap(err, "checkRouteExist")
		return
	}
	if isRouteExist {
		err = status.Error(codes.AlreadyExists, "tunnel already exist")
		return //Not exist
	}
	var lnk netlink.Link
	if lnk, err = netlink.LinkByName(tunnelName); err != nil {
		err = errors.Wrapf(err, "netlink.LinkByName(%s)", tunnelName)
		return
	}
	rt := netlink.Route{
		LinkIndex: lnk.Attrs().Index,
		Dst:       hcDestNetIPNet,
		Table:     table,
	}
	srv.addSpanDbgEvent(ctx, span, "netlink.RouteAdd",
		trace.WithAttributes(
			attribute.Int("LinkIndex", rt.LinkIndex),
			attribute.Stringer("Dst", rt.Dst),
			attribute.Int("Table", rt.Table),
		),
	)
	if err = netlink.RouteAdd(&rt); err != nil {
		err = errors.Wrap(err, "netlink.RouteAdd")
		return
	}
	srv.addSpanDbgEvent(ctx, span, "newRpFilter",
		trace.WithAttributes(
			attribute.String("tunnelName", tunnelName),
		),
	)
	if err = srv.newRpFilter(ctx, tunnelName); err != nil {
		err = errors.Wrapf(err, "newRpFilter(%s)", tunnelName)
	}
	return //nolint:nakedret
}

//RemoveRoute impl service
func (srv *routeService) RemoveRoute(ctx context.Context, req *route.RemoveRouteRequest) (resp *emptypb.Empty, err error) {
	hcDestIP := req.GetHcDestIP()
	hcTunDestIP := req.GetHcTunDestIP()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("hcDestIP", hcDestIP),
		attribute.String("hcTunDestIP", hcTunDestIP),
	)

	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()
	resp = new(emptypb.Empty)
	var (
		hcTunDestNetIP net.IP
		hcDestNetIPNet *net.IPNet
	)

	if hcTunDestNetIP, _, err = net.ParseCIDR(hcTunDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "'hcTunDestIP': %v",
			errors.Wrap(err, "net.ParseCIDR"),
		)
		return
	}
	span.SetAttributes(attribute.Stringer("hcTunDestNetIP", hcTunDestNetIP))

	if _, hcDestNetIPNet, err = net.ParseCIDR(hcDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "'hcDestIP': %v",
			errors.Wrap(err, "net.ParseCIDR"),
		)
		return
	}
	span.SetAttributes(attribute.Stringer("hcDestNetIPNet", hcDestNetIPNet))

	table := int(intNet.IPType(hcTunDestNetIP).Int())
	srv.addSpanDbgEvent(ctx, span, "checkRouteExist",
		trace.WithAttributes(
			attribute.Stringer("hcDestNetIPNet", hcDestNetIPNet),
			attribute.Int("table", table),
		),
	)
	var exist bool
	exist, err = srv.checkRouteExist(ctx, hcDestNetIPNet.IP.String(), fmt.Sprintf("%v", table))
	if err != nil {
		err = errors.Wrapf(err, "checkRouteExist")
		return
	}
	if !exist {
		err = status.Errorf(codes.NotFound, "route for scope 'HcDestIP':%v, 'HcTunDestIP':%v is not found",
			hcDestIP, hcTunDestIP)
		return
	}
	tunnelName := fmt.Sprintf("tun%v", table)
	var lnk netlink.Link
	if lnk, err = netlink.LinkByName(tunnelName); err != nil {
		err = errors.Wrapf(err, "netlink.LinkByName(%s)", tunnelName)
		return
	}
	rt := netlink.Route{
		LinkIndex: lnk.Attrs().Index,
		Dst:       hcDestNetIPNet,
		Table:     table,
	}
	srv.addSpanDbgEvent(ctx, span, "netlink.RouteDel",
		trace.WithAttributes(
			attribute.Int("LinkIndex", rt.LinkIndex),
			attribute.Stringer("Dst", rt.Dst),
			attribute.Int("Table", rt.Table),
		),
	)
	if err = netlink.RouteDel(&rt); err != nil {
		err = errors.Wrap(err, "netlink.RouteDel")
		return
	}
	return //nolint:nakedret
}

//GetState impl service
func (srv *routeService) GetState(ctx context.Context, _ *emptypb.Empty) (resp *route.GetStateResponse, err error) {
	const (
		cmd  = "ip"
		args = "route list table all"
	)

	var leave func()
	leave, err = srv.enter(ctx)
	if err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	outBuf := bytes.NewBuffer(nil)
	var ec int
	if ec, err = srv.execExternal(ctx, outBuf, cmd, args); err != nil {
		err = errors.Wrapf(err, "exec-of:%s %s", cmd, args)
		return
	}
	if ec != 0 {
		err = errors.Errorf("exec-of:%s %s -> exit-code(%d)", cmd, args, ec)
		return
	}
	resp = &route.GetStateResponse{
		Routes: srv.parseRoutes(outBuf.Bytes()),
	}
	return
}

func (srv *routeService) checkRouteExist(ctx context.Context, destIP string, tunnelName string) (bool, error) {
	cmd := "ip"
	args := fmt.Sprintf("route show %s table %s", destIP, tunnelName)
	out := bytes.NewBuffer(nil)
	ec, err := srv.execExternal(ctx, out, cmd, args)
	var isExist bool
	if err != nil {
		err = errors.Wrapf(err, "exec-of: %s %s", cmd, args)
	} else {
		switch ec {
		case 0:
			routes := srv.parseRoutes(out.Bytes())
			for _, r := range routes {
				isExist = strings.Contains(r, destIP) &&
					strings.Contains(r, tunnelName)
				if isExist {
					break
				}
			}
			fallthrough
		case 2:
		default:
			err = errors.Errorf("exec-of: %s %s -> exit-code(%v)", cmd, args, ec)
		}
	}
	return isExist, err
}

func (srv *routeService) parseRoutes(raw []byte) []string {
	var res []string
	var ip net.IP
	found := reIPAndTun.FindAllStringSubmatch(string(raw), -1)
	for _, items := range found {
		if len(items) >= 3 && (&ip).UnmarshalText([]byte(items[1])) == nil {
			n, e := strconv.Atoi(items[2])
			if e == nil {
				res = append(res, fmt.Sprintf("%s:%v", ip, n))
			}
		}
	}
	sort.Strings(res)
	slice.DedupSlice(&res, func(i, j int) bool {
		return strings.EqualFold(res[i], res[j])
	})
	return res
}

func (srv *routeService) newRpFilter(ctx context.Context, tunnelName string) error {
	cmd := "sysctl"
	args := fmt.Sprintf("-w net.ipv4.conf.%s.rp_filter=0", tunnelName)
	ec, err := srv.execExternal(ctx, nil, cmd, args)
	if err != nil {
		return errors.Wrapf(err, "exec-of:%s %s", cmd, args)
	}
	if ec != 0 {
		return errors.Errorf("exec-of:%s %s -> exit-code(%v)", cmd, args, ec)
	}
	return nil
}

func (srv *routeService) correctError(err error) error {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			err = status.FromContextError(err).Err()
		}
		if status.Code(errors.Cause(err)) == codes.Unknown {
			err = status.Errorf(codes.Internal, "%v", err)
		}
	}
	return err
}

func (srv *routeService) execExternal(ctx context.Context, output io.Writer, command string, args ...string) (exitCode int, err error) {
	cmd := exec.Command(command, args...) //nolint:gosec
	if output != nil {
		cmd.Stdout = output
	}
	if err = cmd.Start(); err != nil {
		return
	}
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		ch <- cmd.Wait()
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-srv.appCtx.Done():
		err = srv.appCtx.Err()
	case err = <-ch:
		if err == nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		_ = cmd.Process.Kill()
	}
	return
}

func (srv *routeService) addSpanDbgEvent(ctx context.Context, span trace.Span, eventName string, opts ...trace.EventOption) {
	if logger.IsLevelEnabled(ctx, zap.DebugLevel) {
		span.AddEvent(eventName, opts...)
	}
}

func (srv *routeService) enter(ctx context.Context) (leave func(), err error) {
	select {
	case <-srv.appCtx.Done():
		err = srv.appCtx.Err()
	case <-ctx.Done():
		err = ctx.Err()
	case srv.sema <- struct{}{}:
		var o sync.Once
		leave = func() {
			o.Do(func() {
				<-srv.sema
			})
		}
		return
	}
	err = status.FromContextError(err).Err()
	return
}
