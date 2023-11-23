package agent

import (
	"net"
	"os"

	"github.com/criteo/haproxy-spoe-auth/internal/auth"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"
	"github.com/sirupsen/logrus"
)

// NotAuthenticatedMessage SPOE response stating the user is not authenticated
var NotAuthenticatedMessage = action.NewSetVar(action.ScopeSession, "is_authenticated", false)

// AuthenticatedMessage SPOE response stating the user is authenticated
var AuthenticatedMessage = action.NewSetVar(action.ScopeSession, "is_authenticated", true)

// StartAgent start the agent
func StartAgent(interfaceAddr string, authenticators map[string]auth.Authenticator) {
	agent := agent.New(func(request *request.Request) {
		var authenticated bool = false
		var hasError bool = false
		var sPOEMessageFound bool = false

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			// Dump all messages from HAProxy for debug purposes.
			logrus.WithFields(logrus.Fields{
				"spoe_request_engine_id": request.EngineID,
				"spoe_request_frame_id":  request.FrameID,
				"spoe_request_stream_id": request.StreamID,
				"spoe_request_actions":   request.Actions,
				"spoe_request_messages":  request.Messages,
			}).Debug("Received SPOE request")
		}

		for authentifier_name, authentifier := range authenticators {
			msg, err := request.Messages.GetByName(authentifier_name)
			if err == nil {
				sPOEMessageFound = true

				var log = logrus.WithField("authenticator", authentifier_name)

				log.Debugf("new message with name %s received", msg.Name)

				isAuthenticated, replyActions, err := authentifier.Authenticate(msg)
				if err != nil {
					log.Errorf("unable to authenticate user: %v", err)
					hasError = true
					break
				}
				request.Actions = append(request.Actions, replyActions...)

				if isAuthenticated {
					authenticated = true
				}
				log.WithField("isAuthenticated", isAuthenticated).Debug("Authentication result")

				break
			}
		}

		if !sPOEMessageFound {
			logrus.Error("Agent request does not contain a message matching configured authenticators, please check " +
				"that 'spoe-message' directive in HAProxy SPOE engine config " +
				"matches .ldap.spoe_message and/or .oidc.spoe_message configuration fields in the agent config")
		}

		if hasError {
			request.Actions = append(request.Actions, auth.BuildHasErrorMessage())
		} else {
			if authenticated {
				request.Actions = append(request.Actions, AuthenticatedMessage)
			} else {
				request.Actions = append(request.Actions, NotAuthenticatedMessage)
			}
		}
	}, logger.NewDefaultLog())

	listener, err := net.Listen("tcp", interfaceAddr)
	if err != nil {
		logrus.Printf("error create listener, %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	logrus.Infof("agent starting and listening on %s with %d authenticators", interfaceAddr, len(authenticators))
	if err := agent.Serve(listener); err != nil {
		logrus.Fatal(err)
	}
}
