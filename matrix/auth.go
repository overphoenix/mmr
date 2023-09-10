package matrix

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/turt2live/matrix-media-repo/common/rcontext"
	"github.com/turt2live/matrix-media-repo/util"
)

var ErrInvalidToken = errors.New("missing or invalid access token")
var ErrGuestToken = errors.New("token belongs to a guest")
var ErrNoXMatrixAuth = errors.New("no X-Matrix auth headers")

func doBreakerRequest(ctx rcontext.RequestContext, serverName string, accessToken string, appserviceUserId string, ipAddr string, method string, path string, resp interface{}) error {
	if accessToken == "" {
		return ErrInvalidToken
	}

	hs, cb := getBreakerAndConfig(serverName)

	var replyError error
	var authError error
	replyError = cb.CallContext(ctx, func() error {
		query := map[string]string{}
		if appserviceUserId != "" {
			query["user_id"] = appserviceUserId
		}

		target, _ := url.Parse(util.MakeUrl(hs.ClientServerApi, path))
		q := target.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		target.RawQuery = q.Encode()
		err := doRequest(ctx, method, target.String(), nil, resp, accessToken, ipAddr)
		if err != nil {
			ctx.Log.Debug("Error from homeserver: ", err)
			err, authError = filterError(err)
			return err
		}
		return nil
	}, 1*time.Minute)

	if authError != nil {
		return authError
	}
	return replyError
}

func GetUserIdFromToken(ctx rcontext.RequestContext, serverName string, accessToken string, appserviceUserId string, ipAddr string) (string, error) {
	response := &userIdResponse{}
	err := doBreakerRequest(ctx, serverName, accessToken, appserviceUserId, ipAddr, "GET", "/_matrix/client/v3/account/whoami", response)
	if err != nil {
		return "", err
	}
	if response.IsGuest || response.IsGuest2 {
		return "", ErrGuestToken
	}
	return response.UserId, nil
}

func Logout(ctx rcontext.RequestContext, serverName string, accessToken string, appserviceUserId string, ipAddr string) error {
	response := &emptyResponse{}
	err := doBreakerRequest(ctx, serverName, accessToken, appserviceUserId, ipAddr, "POST", "/_matrix/client/v3/logout", response)
	if err != nil {
		return err
	}
	return nil
}

func LogoutAll(ctx rcontext.RequestContext, serverName string, accessToken string, appserviceUserId string, ipAddr string) error {
	response := &emptyResponse{}
	err := doBreakerRequest(ctx, serverName, accessToken, appserviceUserId, ipAddr, "POST", "/_matrix/client/v3/logout/all", response)
	if err != nil {
		return err
	}
	return nil
}

func ValidateXMatrixAuth(request *http.Request, expectNoContent bool) (string, error) {
	if !expectNoContent {
		panic("development error: X-Matrix auth validation can only be done with an empty body for now")
	}

	auths, err := util.GetXMatrixAuth(request)
	if err != nil {
		return "", err
	}

	if len(auths) == 0 {
		return "", ErrNoXMatrixAuth
	}

	obj := map[string]interface{}{
		"method":      request.Method,
		"uri":         request.RequestURI,
		"origin":      auths[0].Origin,
		"destination": auths[0].Destination,
		"content":     "{}",
	}
	canonical, err := util.EncodeCanonicalJson(obj)
	if err != nil {
		return "", err
	}

	keys, err := QuerySigningKeys(auths[0].Origin)
	if err != nil {
		return "", err
	}

	for _, h := range auths {
		if h.Origin != obj["origin"] {
			return "", errors.New("auth is from multiple servers")
		}
		if h.Destination != obj["destination"] {
			return "", errors.New("auth is for multiple servers")
		}
		if h.Destination != "" && !util.IsServerOurs(h.Destination) {
			return "", errors.New("unknown destination")
		}

		if key, ok := (*keys)[h.KeyId]; ok {
			if !ed25519.Verify(key, canonical, h.Signature) {
				return "", fmt.Errorf("failed signatures on '%s'", h.KeyId)
			}
		} else {
			return "", fmt.Errorf("unknown key '%s'", h.KeyId)
		}
	}

	return auths[0].Origin, nil
}
