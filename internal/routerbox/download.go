package routerbox

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type downloadOptions struct{ UserAgent, Proxy string }

func downloadError(err error) error {
	var dns *net.DNSError
	var cert x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var timeout net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return errors.New("загрузка отменена")
	case errors.As(err, &dns):
		return errors.New("не удалось разрешить имя: ошибка DNS")
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &hostname):
		return errors.New("TLS: сертификат сервера не прошёл проверку")
	case errors.As(err, &timeout) && timeout.Timeout():
		return errors.New("превышено время ожидания загрузки")
	default:
		return errors.New("не удалось установить соединение с сервером")
	}
}

func fetchDocument(ctx context.Context, address string, limit int64) ([]byte, http.Header, error) {
	return fetchDocumentOptions(ctx, address, limit, downloadOptions{})
}
func fetchDocumentOptions(ctx context.Context, address string, limit int64, opts downloadOptions) ([]byte, http.Header, error) {
	if err := validateURL(address); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second}
	if opts.Proxy != "" {
		p, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, nil, errors.New("некорректный прокси загрузки")
		}
		transport.Proxy = http.ProxyURL(p)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("слишком много перенаправлений")
		}
		if err := validateURL(req.URL.String()); err != nil {
			return err
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("понижение HTTPS запрещено")
		}
		return nil
	}}
	agent := opts.UserAgent
	if agent == "" {
		agent = "RouterBox/" + Version + " sing-box"
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, nil, downloadError(ctx.Err())
			case <-timer.C:
			}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
		if err != nil {
			return nil, nil, errors.New("некорректный адрес загрузки")
		}
		req.Header.Set("User-Agent", agent)
		res, err := client.Do(req)
		if err != nil {
			last = downloadError(err)
			if ctx.Err() != nil {
				return nil, nil, last
			}
			continue
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			last = fmt.Errorf("ошибка загрузки HTTP %d", res.StatusCode)
			if res.StatusCode != 408 && res.StatusCode != 429 && res.StatusCode < 500 {
				return nil, nil, last
			}
			continue
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
		res.Body.Close()
		if err != nil {
			last = errors.New("соединение прервано при загрузке")
			continue
		}
		if int64(len(b)) > limit {
			return nil, nil, errors.New("превышен допустимый размер загрузки")
		}
		return b, res.Header, nil
	}
	return nil, nil, last
}

func (m *Manager) subscriptionDownload(p Subscription) ([]byte, http.Header, error) {
	opts := downloadOptions{UserAgent: p.UserAgent}
	if p.DownloadVia == "vpn" {
		if m.process == nil {
			return nil, nil, errors.New("для обновления через VPN сначала включите VPN с рабочим правилом")
		}
		groups := m.runtimeGroups()
		if len(groups) == 0 {
			return nil, nil, errors.New("нет VPN-маршрута для загрузки подписки")
		}
		chosen := false
		for _, g := range groups {
			if strings.HasSuffix(g.ID, "-udp") {
				continue
			}
			selected := m.selections[g.ID]
			if (selected != "" && selected != "unavailable" && selected != "direct") || g.Mode == "manual" {
				if _, err := m.coreAPI("PUT", "/proxies/subscription-out", Object{"name": groupTag(g.ID)}, 3); err != nil {
					return nil, nil, errors.New("не удалось выбрать VPN-маршрут загрузки")
				}
				chosen = true
				break
			}
		}
		if !chosen {
			return nil, nil, errors.New("нет доступного VPN-сервера для загрузки; прямой выход не используется")
		}
		u := &url.URL{Scheme: "http", Host: "127.0.0.1:9098", User: url.UserPassword("routerbox", m.secret)}
		opts.Proxy = u.String()
	}
	return fetchDocumentOptions(m.ctx, p.URL, MaxDownload, opts)
}
func dnsTimeout(s Settings) int {
	if s.DNSTimeout == 0 {
		return 10
	}
	return s.DNSTimeout
}
func validAgent(agent string) bool {
	return len(agent) <= 256 && !strings.ContainsAny(agent, "\r\n\x00")
}

func defaultSeconds(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}
