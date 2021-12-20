package route

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

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
	const api = "route/GetSwaggerDocs"
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

	devPart    = `dev\s+(\w+)`
	tabPart    = `table\s+(\w+)`
	ipDevTable = `(?mi)(?:\s|^)(` + ip4parts + `)\s+` + devPart + `\s+` + tabPart + `(?:\s|$)`

	mask32 = "/32"
)

var (
	reIPAndTun = regexp.MustCompile(ipAndTun)
	reRoute    = regexp.MustCompile(ipDevTable)
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
	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	hcDestIP := req.GetHcDestIP()
	hcTunDestIP := req.GetHcTunDestIP()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("hcDestIP", hcDestIP),
		attribute.String("hcTunDestIP", hcTunDestIP),
	)

	resp = new(emptypb.Empty)
	var (
		hcTunDestNetIP net.IP
		hcDestNetIP    net.IP
		hcDestNetIPNet *net.IPNet
	)
	if hcTunDestNetIP, _, err = net.ParseCIDR(hcTunDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "bad 'hcTunDestIP': %v",
			errors.WithMessagef(err, "net.ParseCIDR('%s')", hcTunDestIP+mask32),
		)
		return
	}
	span.SetAttributes(attribute.Stringer("hcTunDestNetIP", hcTunDestNetIP))

	if hcDestNetIP, hcDestNetIPNet, err = net.ParseCIDR(hcDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "bad 'hcDestIP': %v",
			errors.WithMessagef(err, "net.ParseCIDR('%s')", hcDestIP+mask32),
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
	var lnk netlink.Link
	if lnk, err = netlink.LinkByName(tunnelName); err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			err = errors.Errorf("tunnel '%s(%s)' is not found", tunnelName, hcTunDestIP)
		} else {
			err = errors.WithMessagef(err, "netlink/LinkByName '%s'", tunnelName)
		}
		return
	}
	if _, ok := lnk.(*netlink.Iptun); !ok {
		err = errors.Errorf("tunnel '%s(%s)' is not 'ipip' type", tunnelName, hcTunDestIP)
		return
	}
	rt := netlink.Route{
		LinkIndex: lnk.Attrs().Index,
		Dst:       hcDestNetIPNet,
		Table:     table,
	}
	srv.addSpanDbgEvent(ctx, span, "netlink/RouteAdd",
		trace.WithAttributes(
			attribute.Int("link-index", rt.LinkIndex),
			attribute.Stringer("dest", rt.Dst),
			attribute.Int("table", rt.Table),
		),
	)
	if err = netlink.RouteAdd(&rt); err != nil {
		var en syscall.Errno
		if errors.As(err, &en) && en == syscall.EEXIST {
			err = status.Errorf(codes.NotFound, "route '%s' -> '%s' already exist", hcDestNetIP, hcTunDestNetIP)
		} else {
			err = errors.Wrap(err, "netlink/RouteAdd")
		}
		return
	}
	return resp, err
}

//RemoveRoute impl service
func (srv *routeService) RemoveRoute(ctx context.Context, req *route.RemoveRouteRequest) (resp *emptypb.Empty, err error) {
	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	hcDestIP := req.GetHcDestIP()
	hcTunDestIP := req.GetHcTunDestIP()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("hcDestIP", hcDestIP),
		attribute.String("hcTunDestIP", hcTunDestIP),
	)

	resp = new(emptypb.Empty)
	var (
		hcTunDestNetIP net.IP
		hcDestNetIPNet *net.IPNet
	)

	if hcTunDestNetIP, _, err = net.ParseCIDR(hcTunDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "bad 'hcTunDestIP': %v",
			errors.WithMessagef(err, "net.ParseCIDR('%s')", hcTunDestIP+mask32),
		)
		return
	}
	span.SetAttributes(attribute.Stringer("hcTunDestNetIP", hcTunDestNetIP))

	if _, hcDestNetIPNet, err = net.ParseCIDR(hcDestIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "bad 'hcDestIP': %v",
			errors.WithMessagef(err, "net.ParseCIDR('%s')", hcDestIP+mask32),
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
	tunnelName := fmt.Sprintf("tun%v", table)
	var lnk netlink.Link
	if lnk, err = netlink.LinkByName(tunnelName); err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			err = errors.Errorf("tunnel '%s(%s)' is not found", tunnelName, hcTunDestIP)
		} else {
			err = errors.WithMessagef(err, "netlink/LinkByName '%s'", tunnelName)
		}
		return
	}
	if _, ok := lnk.(*netlink.Iptun); !ok {
		err = errors.Errorf("tunnel '%s(%s)' is not 'ipip' type", tunnelName, hcTunDestIP)
		return
	}
	rt := netlink.Route{
		LinkIndex: lnk.Attrs().Index,
		Dst:       hcDestNetIPNet,
		Table:     table,
	}
	srv.addSpanDbgEvent(ctx, span, "netlink/RouteDel",
		trace.WithAttributes(
			attribute.Int("link-index", rt.LinkIndex),
			attribute.Stringer("dest", rt.Dst),
			attribute.Int("table", rt.Table),
		),
	)
	if err = netlink.RouteDel(&rt); err != nil {
		var en syscall.Errno
		if errors.As(err, &en) && en == syscall.ESRCH {
			err = status.Errorf(codes.NotFound, "route '%s' -> '%s' is not found", hcDestIP, hcDestNetIPNet)
		} else {
			err = errors.Wrap(err, "netlink/RouteDel")
		}
	}
	return resp, err
}

//GetState impl service
func (srv *routeService) GetState(ctx context.Context, _ *emptypb.Empty) (resp *route.GetStateResponse, err error) {
	const (
		cmd  = "ip"
		args = "route list table all"
	)

	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	devices := make(map[string]net.IP)
	var links []netlink.Link
	if links, err = netlink.LinkList(); err != nil {
		err = errors.Wrap(err, "netlink/LinkList")
		return
	}

	for _, l := range links {
		switch tun := l.(type) {
		case *netlink.Iptun:
			devices[tun.Name] = tun.Remote
		}
	}

	resp = new(route.GetStateResponse)
	outBuf := bytes.NewBuffer(nil)
	var ec int
	if ec, err = srv.execExternal(ctx, outBuf, cmd, strings.Split(args, " ")...); err != nil {
		err = errors.WithMessagef(err, "exec-of '%s %s'", cmd, args)
	}
	if ec != 0 {
		err = errors.Errorf("exec-of '%s %s' -> exit code %d", cmd, args, ec)
		return
	}
	err = srv.parseRoutes2(outBuf.Bytes(), func(ip net.IP, dev, table string) error {
		if ipTun := devices[dev]; ipTun != nil {
			resp.Routes = append(resp.Routes, &route.Route{
				HcDestIP:    ip.String(),
				HcTunDestIP: ipTun.String(),
				Dev:         dev,
				Table:       table,
			})
		}
		return nil
	})
	return resp, err
}

/*//TODO: Пока оставим этот код а там поглядим
func (srv *routeService) checkRouteExist(ctx context.Context, destIP net.IP, tunnel int) (bool, error) {
	const cmd = "ip"
	args := fmt.Sprintf("route show %s table %v", destIP, tunnel)
	out := bytes.NewBuffer(nil)
	ec, err := srv.execExternal(ctx, out, cmd, strings.Split(args, " ")...)
	var isExist bool
	if err != nil {
		err = errors.WithMessagef(err, "exec-of '%s %s'", cmd, args)
	} else if ec == 0 {
		isExist = reIPAndTun.Match(out.Bytes())
	} else {
		err = errors.Errorf("exec-of '%s %s' -> exit code %v", cmd, args, ec)
	}
	return isExist, err
}
*/

type parecedRouteCb = func(ip net.IP, dev, table string) error

func (srv *routeService) parseRoutes2(raw []byte, cb parecedRouteCb) error {
	matched := reRoute.FindAllStringSubmatch(string(raw), -1)
	for _, items := range matched {
		var ip net.IP
		if len(items) >= 4 && (&ip).UnmarshalText([]byte(items[1])) == nil {
			dev, tab := items[2], items[3]
			if err := cb(ip, dev, tab); err != nil {
				return err
			}
		}
	}
	return nil
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

func (srv *routeService) correctError(err error) error {
	if err != nil && status.Code(err) == codes.Unknown {
		switch errors.Cause(err) {
		case context.DeadlineExceeded:
			return status.New(codes.DeadlineExceeded, err.Error()).Err()
		case context.Canceled:
			return status.New(codes.Canceled, err.Error()).Err()
		default:
			if e := new(url.Error); errors.As(err, &e) {
				switch errors.Cause(e.Err) {
				case context.Canceled:
					return status.New(codes.Canceled, err.Error()).Err()
				case context.DeadlineExceeded:
					return status.New(codes.DeadlineExceeded, err.Error()).Err()
				default:
					if e.Timeout() {
						return status.New(codes.DeadlineExceeded, err.Error()).Err()
					}
				}
			}
			err = status.New(codes.Internal, err.Error()).Err()
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
		} else if e := new(*exec.ExitError); errors.As(err, e) {
			exitCode = (*e).ExitCode()
			err = nil
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
