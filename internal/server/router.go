package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	ErrorServiceNotFound             = errors.New("service not found")
	ErrorTargetFailedToBecomeHealthy = errors.New("target failed to become healthy within configured timeout")
	ErrorHostInUse                   = errors.New("host settings conflict with another service")
	ErrorNoServerName                = errors.New("no server name provided")
	ErrorUnknownServerName           = errors.New("unknown server name")

	contextKeyRoutingContext = contextKey("routing-context")
)

type routingContext struct {
	MatchedPrefix string
}

func RoutingContext(r *http.Request) *routingContext {
	rc, ok := r.Context().Value(contextKeyRoutingContext).(*routingContext)
	if !ok {
		return nil
	}
	return rc
}

func RoutedTargetPath(r *http.Request) string {
	path := r.URL.Path
	if rc := RoutingContext(r); rc != nil {
		path = strings.TrimPrefix(path, rc.MatchedPrefix)
		if path == "" {
			path = rootPath
		}
	}
	return path
}

type Router struct {
	statePath            string
	services             *ServiceMap
	serviceLock          sync.RWMutex
	saveLock             sync.Mutex
	recheckOnRestore     bool
	sanCertManager       *SANCertManager
	dynamicDomainManager *DynamicDomainManager
	certRegistry         *CertificateRegistry
}

type ServiceDescription struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	TLS    bool   `json:"tls"`
	Target string `json:"target"`
	State  string `json:"state"`

	// Structured variants of the display fields above. Only ever append fields
	// here — the CLI and server may briefly run different versions during a
	// proxy replacement, and gob tolerates added fields but not changed ones.
	Hosts          []string `json:"hosts,omitempty"`
	PathPrefixes   []string `json:"path_prefixes,omitempty"`
	Targets        []string `json:"targets,omitempty"`
	ReaderTargets  []string `json:"reader_targets,omitempty"`
	RolloutTargets []string `json:"rollout_targets,omitempty"`
}

type ServiceDescriptionMap map[string]ServiceDescription

func NewRouter(statePath string) *Router {
	return &Router{
		statePath: statePath,
		services:  NewServiceMap(),
	}
}

// EnableTargetRecheckOnRestore makes RestoreLastSavedState re-verify restored
// targets with live health checks instead of assuming they are still healthy.
func (r *Router) EnableTargetRecheckOnRestore() {
	r.recheckOnRestore = true
}

func (r *Router) SetSANCertManager(manager *SANCertManager) {
	r.withWriteLock(func() error {
		r.sanCertManager = manager

		for _, service := range r.services.All() {
			service.SetSANCertManager(manager)
		}
		return nil
	})
}

func (r *Router) SANCertManager() *SANCertManager {
	return r.sanCertManager
}

// SetDynamicDomainManager installs the dynamic domain coordinator and
// reconciles it with the already-restored services.
func (r *Router) SetDynamicDomainManager(manager *DynamicDomainManager) {
	services := map[string]ServiceOptions{}

	r.withReadLock(func() error {
		r.dynamicDomainManager = manager

		for name, service := range r.services.All() {
			services[name] = service.options
		}
		return nil
	})

	for name, options := range services {
		manager.ServiceDeployed(name, options)
	}
}

func (r *Router) DynamicDomainManager() *DynamicDomainManager {
	return r.dynamicDomainManager
}

// SetCertificateRegistry sets the central certificate registry for the router
func (r *Router) SetCertificateRegistry(registry *CertificateRegistry) {
	r.certRegistry = registry
}

// GetCertificateRegistry returns the certificate registry if available
func (r *Router) GetCertificateRegistry() *CertificateRegistry {
	return r.certRegistry
}

func (r *Router) RestoreLastSavedState() error {
	// Under the atomic-write protocol a leftover temp file is by definition an
	// aborted partial write — never restore from it.
	tmpPath := r.statePath + ".tmp"
	if err := os.Remove(tmpPath); err == nil {
		slog.Warn("Removed stale state temp file from an interrupted save", "path", tmpPath)
	}

	data, err := os.ReadFile(r.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("No previous state to restore", "path", r.statePath)
			return nil
		}
		slog.Error("Failed to restore saved state", "path", r.statePath, "error", err)
		return err
	}

	services, err := decodeStateServices(data)
	if err != nil {
		slog.Error("Failed to decode saved state", "path", r.statePath, "error", err)

		services, err = r.restoreFromBackup(err)
		if err != nil {
			return err
		}
	} else {
		// Keep a last-known-good copy to recover from a future torn write.
		if err := writeFileAtomic(r.backupPath(), data, 0644); err != nil {
			slog.Warn("Failed to write state backup", "path", r.backupPath(), "error", err)
		}
	}

	r.withWriteLock(func() error {
		r.services = NewServiceMap()
		for _, service := range services {
			r.services.Set(service)
		}

		return nil
	})

	if r.recheckOnRestore {
		for _, service := range services {
			service.RecheckTargetHealth()
		}
	}

	slog.Info("Restored saved state", "path", r.statePath)
	return nil
}

func (r *Router) restoreFromBackup(cause error) ([]*Service, error) {
	data, err := os.ReadFile(r.backupPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Error("Failed to read state backup", "path", r.backupPath(), "error", err)
		}
		return nil, cause
	}

	services, err := decodeStateServices(data)
	if err != nil {
		slog.Error("Failed to decode state backup", "path", r.backupPath(), "error", err)
		return nil, errors.Join(cause, err)
	}

	slog.Warn("Restored state from backup after decode failure", "path", r.backupPath())

	// Repair the primary so subsequent boots restore cleanly again.
	if err := writeFileAtomic(r.statePath, data, 0644); err != nil {
		slog.Warn("Failed to repair state file from backup", "path", r.statePath, "error", err)
	}

	return services, nil
}

func (r *Router) backupPath() string {
	return r.statePath + ".bak"
}

// stateEnvelope is the future versioned on-disk state format. The writer still
// emits a bare JSON array so that older generations can read its output; the
// reader accepts both forms so the writer can switch once every deployed
// generation understands the envelope.
type stateEnvelope struct {
	Version  int        `json:"version"`
	Services []*Service `json:"services"`
}

func decodeStateServices(data []byte) ([]*Service, error) {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)

	if len(trimmed) > 0 && trimmed[0] == '{' {
		var envelope stateEnvelope
		if err := json.Unmarshal(trimmed, &envelope); err != nil {
			return nil, err
		}
		return envelope.Services, nil
	}

	var services []*Service
	if err := json.Unmarshal(trimmed, &services); err != nil {
		return nil, err
	}
	return services, nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	service, prefix := r.serviceForRequest(req)
	if service == nil {
		SetErrorResponse(w, req, http.StatusNotFound, nil)
		return
	}

	if service.options.StripPrefix && prefix != rootPath {
		ctx := context.WithValue(req.Context(), contextKeyRoutingContext, &routingContext{MatchedPrefix: prefix})
		req = req.WithContext(ctx)
	}

	service.ServeHTTP(w, req)
}

func (r *Router) DeployService(name string, targetURLs, readerURLs []string, options ServiceOptions, targetOptions TargetOptions, deploymentOptions DeploymentOptions) error {
	if err := options.Validate(); err != nil {
		return err
	}

	options.Normalize()
	slog.Info("Deploying", "service", name, "targets", targetURLs, "hosts", options.Hosts, "paths", options.PathPrefixes, "tls", options.TLSEnabled)

	lb, err := r.createLoadBalancer(targetURLs, readerURLs, options, targetOptions, deploymentOptions)
	if err != nil {
		return err
	}

	replaced, err := r.installLoadBalancer(name, TargetSlotActive, lb, options, func() (*Service, error) {
		return r.createOrUpdateService(name, options, targetOptions)
	})
	if err != nil {
		return err
	}

	if replaced != nil {
		replaced.Dispose()
		replaced.DrainAll(deploymentOptions.DrainTimeout)
	}

	if r.dynamicDomainManager != nil {
		r.dynamicDomainManager.ServiceDeployed(name, options)
	}

	slog.Info("Deployed", "service", name, "targets", targetURLs, "hosts", options.Hosts, "paths", options.PathPrefixes, "tls", options.TLSEnabled)
	return nil
}

func (r *Router) SetRolloutTargets(name string, targetURLs, readerURLs []string, deploymentOptions DeploymentOptions) error {
	service := r.serviceForName(name)
	if service == nil {
		return ErrorServiceNotFound
	}

	slog.Info("Deploying for rollout", "service", name, "targets", targetURLs)

	lb, err := r.createLoadBalancer(targetURLs, readerURLs, service.options, service.targetOptions, deploymentOptions)
	if err != nil {
		return err
	}

	replaced, err := r.installLoadBalancer(name, TargetSlotRollout, lb, service.options, func() (*Service, error) {
		return service, nil
	})
	if err != nil {
		return err
	}

	if replaced != nil {
		replaced.Dispose()
		replaced.DrainAll(deploymentOptions.DrainTimeout)
	}

	slog.Info("Deployed for rollout", "service", name, "targets", targetURLs)
	return nil
}

func (r *Router) SetRolloutSplit(name string, percent int, allowList []string) error {
	defer r.saveStateSnapshot()

	service := r.serviceForName(name)
	if service == nil {
		return ErrorServiceNotFound
	}

	return service.SetRolloutSplit(percent, allowList)
}

func (r *Router) StopRollout(name string) error {
	defer r.saveStateSnapshot()

	service := r.serviceForName(name)
	if service == nil {
		return ErrorServiceNotFound
	}

	return service.StopRollout()
}

func (r *Router) RemoveService(name string) error {
	defer r.saveStateSnapshot()

	err := r.withWriteLock(func() error {
		service := r.services.Get(name)
		if service == nil {
			return ErrorServiceNotFound
		}

		service.Dispose()
		r.services.Remove(service.name)

		return nil
	})
	if err != nil {
		return err
	}

	if r.dynamicDomainManager != nil {
		r.dynamicDomainManager.ServiceRemoved(name)
	}

	return nil
}

func (r *Router) PauseService(name string, drainTimeout time.Duration, pauseTimeout time.Duration) error {
	defer r.saveStateSnapshot()

	service := r.serviceForName(name)
	if service == nil {
		return ErrorServiceNotFound
	}

	return service.Pause(drainTimeout, pauseTimeout)
}

func (r *Router) StopService(name string, drainTimeout time.Duration, message string) error {
	defer r.saveStateSnapshot()

	service := r.serviceForName(name)
	if service == nil {
		return ErrorServiceNotFound
	}

	return service.Stop(drainTimeout, message)
}

func (r *Router) ResumeService(name string) error {
	defer r.saveStateSnapshot()

	service := r.serviceForName(name)
	if service == nil {
		return ErrorServiceNotFound
	}

	return service.Resume()
}

func (r *Router) ListActiveServices() ServiceDescriptionMap {
	result := ServiceDescriptionMap{}

	r.withReadLock(func() error {
		for name, service := range r.services.All() {
			if service.active != nil {
				host := strings.Join(service.options.Hosts, ",")
				if host == "" {
					host = "*"
				}

				path := strings.Join(service.options.PathPrefixes, ",")
				target := strings.Join(service.active.Targets().Names(), ",")

				description := ServiceDescription{
					Host:          host,
					Path:          path,
					Target:        target,
					TLS:           service.options.TLSEnabled,
					State:         service.pauseController.GetState().String(),
					Hosts:         service.options.Hosts,
					PathPrefixes:  service.options.PathPrefixes,
					Targets:       service.active.WriteTargets().Names(),
					ReaderTargets: service.active.ReadTargets().Names(),
				}

				if service.rollout != nil {
					description.RolloutTargets = service.rollout.Targets().Names()
				}

				result[name] = description
			}
		}
		return nil
	})

	return result
}

func (r *Router) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		hello.ServerName = r.defaultTLSHostname()

		if hello.ServerName == "" {
			slog.Debug("ACME: Unable to get certificate (no server name)")
			return nil, ErrorNoServerName
		} else {
			slog.Warn("No server name; using default TLS hostname", "host", hello.ServerName)
		}
	}

	// Try the central certificate registry first
	if r.certRegistry != nil {
		cert, err := r.certRegistry.GetCertificate(hello)
		if err == nil {
			return cert, nil
		}
		// If registry returns an error (except not found), log it
		if !errors.Is(err, ErrCertificateNotFound) && !errors.Is(err, ErrCertificatePending) {
			slog.Debug("Certificate registry error", "domain", hello.ServerName, "error", err)
		}
		// Fall through to per-service cert manager
	}

	service := r.serviceForHost(hello.ServerName)
	if service == nil {
		slog.Debug("ACME: Unable to get certificate (unknown server name)")
		return nil, ErrorUnknownServerName
	}

	if service.certManager == nil {
		slog.Debug("ACME: Unable to get certificate (service does not support TLS)")
		return nil, ErrorUnknownServerName
	}

	return service.certManager.GetCertificate(hello)
}

// Private

func (r *Router) createOrUpdateService(name string, options ServiceOptions, targetOptions TargetOptions) (*Service, error) {
	service := r.services.Get(name)
	if service == nil {
		return NewService(name, options, targetOptions, r.sanCertManager)
	}

	err := service.UpdateOptions(options, targetOptions)
	return service, err
}

func (r *Router) createLoadBalancer(targetURLs, readerURLs []string, options ServiceOptions, targetOptions TargetOptions, deploymentOptions DeploymentOptions) (*LoadBalancer, error) {
	tl, err := NewTargetList(targetURLs, readerURLs, targetOptions)
	if err != nil {
		return nil, err
	}

	lb := NewLoadBalancer(tl, options.WriterAffinityTimeout, options.ReadTargetsAcceptWebsockets)

	if !deploymentOptions.Force {
		err = lb.WaitUntilHealthy(deploymentOptions.DeployTimeout)
		if err != nil {
			lb.Dispose()
			return nil, err
		}
	}

	return lb, nil
}

func (r *Router) installLoadBalancer(name string, slot TargetSlot, lb *LoadBalancer, options ServiceOptions, getService func() (*Service, error)) (*LoadBalancer, error) {
	defer r.saveStateSnapshot()

	var replaced *LoadBalancer

	err := r.withWriteLock(func() error {
		conflict := r.services.CheckAvailability(name, options)
		if conflict != nil {
			slog.Error("Host settings conflict with another service", "service", conflict.name)
			return ErrorHostInUse
		}

		service, err := getService()
		if err != nil {
			return err
		}

		replaced = service.UpdateLoadBalancer(lb, slot)
		r.services.Set(service)
		return nil
	})

	return replaced, err
}

// SaveState flushes the current routing state to disk.
func (r *Router) SaveState() error {
	return r.saveStateSnapshot()
}

// DrainAll drains every service's targets concurrently, cancelling hijacked
// connections and waiting out in-flight requests up to timeout.
func (r *Router) DrainAll(timeout time.Duration) {
	services := []*Service{}
	r.withReadLock(func() error {
		for _, service := range r.services.All() {
			if service.active != nil || service.rollout != nil {
				services = append(services, service)
			}
		}
		return nil
	})

	var wg sync.WaitGroup
	for _, service := range services {
		wg.Go(func() { service.Drain(timeout) })
	}
	wg.Wait()
}

func (r *Router) saveStateSnapshot() error {
	services := []*Service{}
	r.withReadLock(func() error {
		for _, service := range r.services.All() {
			services = append(services, service)
		}
		return nil
	})

	data, err := json.Marshal(services)
	if err != nil {
		slog.Error("Unable to save state", "error", err, "path", r.statePath)
		return err
	}

	// Saves are triggered by deferred calls in concurrent RPC handlers, and
	// they share one temp file path — serialize the writers.
	r.saveLock.Lock()
	defer r.saveLock.Unlock()

	if err := writeFileAtomic(r.statePath, data, 0644); err != nil {
		slog.Error("Unable to save state", "error", err, "path", r.statePath)
		return err
	}

	slog.Debug("Saved state", "path", r.statePath)
	return nil
}

func (r *Router) serviceForRequest(req *http.Request) (*Service, string) {
	r.serviceLock.RLock()
	defer r.serviceLock.RUnlock()

	return r.services.ServiceForRequest(req)
}

func (r *Router) serviceForHost(host string) *Service {
	r.serviceLock.RLock()
	defer r.serviceLock.RUnlock()

	return r.services.ServiceForHost(host)
}

func (r *Router) serviceForName(name string) *Service {
	r.serviceLock.RLock()
	defer r.serviceLock.RUnlock()

	return r.services.Get(name)
}

func (r *Router) defaultTLSHostname() string {
	r.serviceLock.RLock()
	defer r.serviceLock.RUnlock()

	return r.services.DefaultTLSHostname()
}

func (r *Router) withReadLock(fn func() error) error {
	r.serviceLock.RLock()
	defer r.serviceLock.RUnlock()

	return fn()
}

func (r *Router) withWriteLock(fn func() error) error {
	r.serviceLock.Lock()
	defer r.serviceLock.Unlock()

	return fn()
}
