package bundleupd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Caps on what we'll buffer from the CDN. Bundles are small YAML (well
// under 100 KB at our scale); sigs are exactly 64 bytes. The 1 MiB / 1 KiB
// caps are an order of magnitude over the largest reasonable case.
const (
	maxBundleBytes = 1 << 20
	maxSigBytes    = 1 << 10
)

// HTTPFetcher fetches the bundle and detached signature via HTTPS GET.
// The two URLs are independent — for the CDN layout in arch §13.5,
// BundleURL is the latest pointer (or a specific version) and SigURL is
// BundleURL + ".sig".
type HTTPFetcher struct {
	BundleURL string
	SigURL    string
	Client    *http.Client
}

// Fetch GETs BundleURL with If-None-Match, then GETs SigURL on a 200.
// A 304 from the bundle endpoint short-circuits and SigURL is not hit.
func (f *HTTPFetcher) Fetch(ctx context.Context, lastETag string) (*FetchResult, error) {
	if f.Client == nil {
		return nil, errors.New("bundleupd: HTTPFetcher.Client is required")
	}
	bundleBytes, etag, notModified, err := f.getWithEtag(ctx, f.BundleURL, lastETag, maxBundleBytes)
	if err != nil {
		return nil, err
	}
	if notModified {
		return &FetchResult{NotModified: true}, nil
	}
	sigBytes, _, _, err := f.getWithEtag(ctx, f.SigURL, "", maxSigBytes)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return &FetchResult{Bundle: bundleBytes, Signature: sigBytes, ETag: etag}, nil
}

func (f *HTTPFetcher) getWithEtag(ctx context.Context, url, lastETag string, cap int64) (body []byte, etag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, err
	}
	if lastETag != "" {
		req.Header.Set("If-None-Match", lastETag)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, resp.Header.Get("ETag"), true, nil
	case http.StatusOK:
		// proceed
	default:
		return nil, "", false, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, cap+1))
	if err != nil {
		return nil, "", false, err
	}
	if int64(len(body)) > cap {
		return nil, "", false, fmt.Errorf("%s: body exceeds %d bytes", url, cap)
	}
	return body, resp.Header.Get("ETag"), false, nil
}
