package app

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/relays-api/internal/services/sentry"
)

type passwordComplexity struct {
	hasUpper   bool
	hasNumber  bool
	hasSpecial bool
}

func writeError(c *gin.Context, status int, errCode string, details map[string]string) {
	response := gin.H{
		"error": errCode,
	}

	if len(details) > 0 {
		response["details"] = details
	}

	c.JSON(status, response)
}

// validatePassword validates password complexity requirements
func validatePassword(password string) error {
	if len(password) < minPasswordLength {
		return errors.New("password_too_short")
	}

	complexity := passwordComplexityFlags([]byte(password))
	if !complexity.hasUpper {
		return errors.New("password_must_contain_uppercase")
	}
	if !complexity.hasNumber {
		return errors.New("password_must_contain_number")
	}
	if !complexity.hasSpecial {
		return errors.New("password_must_contain_special_character")
	}

	return nil
}

func passwordComplexityFlags(password []byte) passwordComplexity {
	var complexity passwordComplexity
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			complexity.hasUpper = true
		case char >= '0' && char <= '9':
			complexity.hasNumber = true
		case (char >= '!' && char <= '/') || (char >= ':' && char <= '@') || (char >= '[' && char <= '`') || (char >= '{' && char <= '~'):
			complexity.hasSpecial = true
		}
		if complexity.hasUpper && complexity.hasNumber && complexity.hasSpecial {
			break
		}
	}

	return complexity
}

// =============================================================================
func (a *App) toSentry(c *gin.Context, handler, errType string, level sentry.Level, err error) {
	a.sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("handler", handler)
		scope.SetExtra("error_type", errType)
		scope.SetLevel(level)
		if reqID := c.GetHeader("X-Request-ID"); reqID != "" {
			scope.SetTag("request_id", reqID)
		}
		a.sentry.CaptureException(err)
	})
}
